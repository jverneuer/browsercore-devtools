/**
 * Certificate inspector — parse PEM/DER X.509 certificates into a summary.
 *
 * Self-contained ASN.1 decoder: walks the TBSCertificate, extracting subject,
 * issuer, validity, SAN, and computing the SHA-256 fingerprint over the whole
 * DER blob. Handles the common DER structures produced by modern CAs; throws
 * {@link CertParseError} on anything it cannot interpret.
 */

import { crypto } from "@network/crypto";
import { CertParseError } from "../errors.js";
import type { CertInfo } from "../types.js";

/** ASN.1 DER tag classes (class + constructed bit live in byte 0). */
const ASN1_UNIVERSAL = 0x00;
const ASN1_CONSTRUCTED = 0x20;

/** Universal tags we care about. */
const TAG_SEQUENCE = 0x10;
const TAG_SET = 0x11;
const TAG_OID = 0x06;
const TAG_UTF8STRING = 0x0c;
const TAG_PRINTABLESTRING = 0x13;
const TAG_IA5STRING = 0x16;
const TAG_UTCTIME = 0x17;
const TAG_GENERALIZEDTIME = 0x18;
const TAG_OCTET_STRING = 0x04;
const TAG_CONTEXT_SPECIFIC = 0x80;

/** OIDs we resolve to short names. */
const OID_NAMES: Readonly<Record<string, string>> = {
    "2.5.4.3": "CN",
    "2.5.4.4": "SN",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.9": "street",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.12": "title",
    "2.5.4.42": "GN",
    "2.5.4.43": "initials",
    "2.5.4.65": "pseudonym",
    "1.2.840.113549.1.9.1": "emailAddress",
    "2.5.29.17": "subjectAltName",
};

/** A cursor over a DER byte buffer. */
class DerCursor {
    private pos = 0;

    constructor(private readonly buf: Uint8Array) {}

    get offset(): number {
        return this.pos;
    }

    get done(): boolean {
        return this.pos >= this.buf.length;
    }

    /** Rewind the cursor to a previously noted offset. */
    rewindTo(offset: number): void {
        this.pos = offset;
    }

    /** Read one ASN.1 TLV: returns tag, constructed flag, and content bytes. */
    readTlv(): { tag: number; constructed: boolean; content: Uint8Array } {
        if (this.done) {
            throw new CertParseError("unexpected end of DER");
        }
        const startTag = this.buf[this.pos++]!;
        const tagClass = startTag & 0xc0;
        const constructed = (startTag & ASN1_CONSTRUCTED) !== 0;
        const tag = startTag & 0x1f;
        if (tagClass !== ASN1_UNIVERSAL && tag !== TAG_CONTEXT_SPECIFIC) {
            throw new CertParseError(`unsupported tag class: 0x${tagClass.toString(16)}`);
        }
        const len = this.readLength();
        if (this.pos + len > this.buf.length) {
            throw new CertParseError(`TLV length ${len} exceeds buffer at offset ${this.pos}`);
        }
        const content = this.buf.subarray(this.pos, this.pos + len);
        this.pos += len;
        return { tag, constructed, content };
    }

    /** Skip one TLV (used when we don't need its contents). */
    skipTlv(): void {
        this.readTlv();
    }

    /** Read a DER length (short or long form, definite only). */
    private readLength(): number {
        if (this.done) {
            throw new CertParseError("truncated DER length");
        }
        const first = this.buf[this.pos++]!;
        if (first < 0x80) {
            return first;
        }
        const nbytes = first & 0x7f;
        if (nbytes === 0 || nbytes > 4) {
            throw new CertParseError(`unsupported DER length form: 0x${first.toString(16)}`);
        }
        let len = 0;
        for (let i = 0; i < nbytes; i++) {
            if (this.done) {
                throw new CertParseError("truncated DER long-form length");
            }
            len = (len << 8) | this.buf[this.pos++]!;
        }
        return len;
    }
}

/** Parse an OID byte content to dotted form. */
function parseOid(content: Uint8Array): string {
    if (content.length === 0) {
        throw new CertParseError("empty OID");
    }
    const first = content[0]!;
    const parts: number[] = [Math.floor(first / 40), first % 40];
    let acc = 0;
    for (let i = 1; i < content.length; i++) {
        const b = content[i]!;
        acc = (acc << 7) | (b & 0x7f);
        if ((b & 0x80) === 0) {
            parts.push(acc);
            acc = 0;
        }
    }
    if (acc !== 0) {
        throw new CertParseError("truncated OID");
    }
    return parts.join(".");
}

/** Decode a string-valued DN attribute (PrintableString/UTF8String/IA5String). */
function decodeStringTag(tag: number, content: Uint8Array): string {
    const decoder = new TextDecoder("utf-8", { fatal: false });
    switch (tag) {
        case TAG_PRINTABLESTRING:
        case TAG_UTF8STRING:
        case TAG_IA5STRING:
            return decoder.decode(content);
        default:
            throw new CertParseError(`unsupported string tag 0x${tag.toString(16)} in DN`);
    }
}

/** Parse a UTCTime or GeneralizedTime content to a Date. */
function parseTime(tag: number, content: Uint8Array): Date {
    const s = new TextDecoder().decode(content);
    let year: number;
    let rest: string;
    if (tag === TAG_UTCTIME) {
        // YYMMDDHHMMSSZ
        const yy = parseInt(s.slice(0, 2), 10);
        year = yy >= 50 ? 1900 + yy : 2000 + yy;
        rest = s.slice(2);
    } else if (tag === TAG_GENERALIZEDTIME) {
        year = parseInt(s.slice(0, 4), 10);
        rest = s.slice(4);
    } else {
        throw new CertParseError(`expected time tag, got 0x${tag.toString(16)}`);
    }
    const month = parseInt(rest.slice(0, 2), 10) - 1;
    const day = parseInt(rest.slice(2, 4), 10);
    const hour = parseInt(rest.slice(4, 6), 10);
    const minute = parseInt(rest.slice(6, 8), 10);
    const second = rest.length >= 10 ? parseInt(rest.slice(8, 10), 10) : 0;
    const tz = rest[rest.length - 1];
    if (tz === "Z") {
        return new Date(Date.UTC(year, month, day, hour, minute, second));
    }
    return new Date(Date.UTC(year, month, day, hour, minute, second));
}

/** Parse an RDNSequence into a single "CN=..., O=..." string. */
function parseDn(content: Uint8Array): string {
    const cursor = new DerCursor(content);
    const rdnParts: string[] = [];
    while (!cursor.done) {
        const rdn = cursor.readTlv();
        if (rdn.tag !== TAG_SET) {
            throw new CertParseError(`expected SET in RDN, got 0x${rdn.tag.toString(16)}`);
        }
        const attrCursor = new DerCursor(rdn.content);
        const attr = attrCursor.readTlv();
        if (attr.tag !== TAG_SEQUENCE) {
            throw new CertParseError(
                `expected SEQUENCE in attribute, got 0x${attr.tag.toString(16)}`,
            );
        }
        const inner = new DerCursor(attr.content);
        const oidTlv = inner.readTlv();
        if (oidTlv.tag !== TAG_OID) {
            throw new CertParseError(`expected OID in attribute`);
        }
        const oid = parseOid(oidTlv.content);
        const valTlv = inner.readTlv();
        const value = decodeStringTag(valTlv.tag, valTlv.content);
        const shortName = OID_NAMES[oid] ?? oid;
        rdnParts.push(`${shortName}=${value}`);
    }
    return rdnParts.join(", ");
}

/** Walk the SAN extension and pull out DNS names (other kinds ignored). */
function parseSan(content: Uint8Array): readonly string[] {
    const cursor = new DerCursor(content);
    const names: string[] = [];
    while (!cursor.done) {
        const tlv = cursor.readTlv();
        // GeneralName: context-specific tag 0x82 = dNSName.
        if (tlv.tag === 0x82) {
            names.push(new TextDecoder().decode(tlv.content));
        }
    }
    return names;
}

/** Parse a TBSCertificate and pull out the fields we surface. */
function parseTbs(tbs: Uint8Array): Omit<CertInfo, "fingerprintSha256"> {
    const cursor = new DerCursor(tbs);
    // First element may be [0] EXPLICIT version — skip if so.
    const first = cursor.readTlv();
    if (first.tag === 0xa0 && first.constructed) {
        return parseTbsBody(cursor);
    }
    return parseTbsRewound(tbs);
}

/** Re-parse after consuming the first TLV when it wasn't the version. */
function parseTbsRewound(tbs: Uint8Array): Omit<CertInfo, "fingerprintSha256"> {
    // Re-create a cursor and skip the version-less first element manually.
    const cursor = new DerCursor(tbs);
    cursor.skipTlv(); // serialNumber
    cursor.skipTlv(); // signature AlgorithmIdentifier
    const issuerTlv = cursor.readTlv(); // issuer
    const issuer = parseDn(issuerTlv.content);
    const validityTlv = cursor.readTlv(); // validity
    const { notBefore, notAfter } = parseValidity(validityTlv.content);
    const subjectTlv = cursor.readTlv(); // subject
    const subject = parseDn(subjectTlv.content);
    // Skip subjectPublicKeyInfo, optional issuer/subject unique IDs.
    let san: readonly string[] = [];
    while (!cursor.done) {
        const tlv = cursor.readTlv();
        // Extensions are in [3] EXPLICIT at the end of TBSCertificate.
        if (tlv.tag === 0xa3 && tlv.constructed) {
            san = parseTbsExtensions(tlv.content);
        }
    }
    return { subject, issuer, notBefore, notAfter, san };
}

/** Parse TBSCertificate body starting after the version wrapper. */
function parseTbsBody(cursor: DerCursor): Omit<CertInfo, "fingerprintSha256"> {
    cursor.skipTlv(); // serialNumber
    cursor.skipTlv(); // signature AlgorithmIdentifier
    const issuerTlv = cursor.readTlv();
    const issuer = parseDn(issuerTlv.content);
    const validityTlv = cursor.readTlv();
    const { notBefore, notAfter } = parseValidity(validityTlv.content);
    const subjectTlv = cursor.readTlv();
    const subject = parseDn(subjectTlv.content);
    // Skip subjectPublicKeyInfo and optional unique IDs.
    let san: readonly string[] = [];
    while (!cursor.done) {
        const tlv = cursor.readTlv();
        if (tlv.tag === 0xa3 && tlv.constructed) {
            san = parseTbsExtensions(tlv.content);
        }
    }
    return { subject, issuer, notBefore, notAfter, san };
}

/** Parse the validity SEQUENCE { notBefore, notAfter }. */
function parseValidity(content: Uint8Array): { notBefore: Date; notAfter: Date } {
    const cursor = new DerCursor(content);
    const nb = cursor.readTlv();
    const na = cursor.readTlv();
    return { notBefore: parseTime(nb.tag, nb.content), notAfter: parseTime(na.tag, na.content) };
}

/** Walk the extensions SEQUENCE and pull out the SAN OID. */
function parseTbsExtensions(content: Uint8Array): readonly string[] {
    const cursor = new DerCursor(content);
    while (!cursor.done) {
        const ext = cursor.readTlv();
        if (ext.tag !== TAG_SEQUENCE) {
            continue;
        }
        const ec = new DerCursor(ext.content);
        const oidTlv = ec.readTlv();
        if (oidTlv.tag !== TAG_OID) {
            continue;
        }
        const oid = parseOid(oidTlv.content);
        if (oid !== "2.5.29.17") {
            continue;
        }
        // Optional critical BOOLEAN — skip if present.
        if (!ec.done) {
            const before = ec.offset;
            const maybeCrit = ec.readTlv();
            if (maybeCrit.tag !== 0x01) {
                ec.rewindTo(before);
            }
        }
        if (ec.done) {
            continue;
        }
        const octetTlv = ec.readTlv();
        if (octetTlv.tag !== TAG_OCTET_STRING) {
            continue;
        }
        return parseSan(octetTlv.content);
    }
    return [];
}

/** Convert raw bytes to lowercase hex. */
function toHex(bytes: Uint8Array): string {
    let out = "";
    for (let i = 0; i < bytes.length; i++) {
        out += bytes[i]!.toString(16).padStart(2, "0");
    }
    return out;
}

/** Strip PEM armor and return the DER body, or null if not PEM. */
function maybePemToDer(input: Uint8Array): Uint8Array | null {
    const text = new TextDecoder("ascii", { fatal: false }).decode(input);
    if (!text.includes("-----BEGIN CERTIFICATE-----")) {
        return null;
    }
    const lines = text.split(/\r?\n/);
    const body: string[] = [];
    let inBody = false;
    for (const line of lines) {
        if (line.startsWith("-----BEGIN ")) {
            inBody = true;
            continue;
        }
        if (line.startsWith("-----END ")) {
            break;
        }
        if (inBody) {
            body.push(line.trim());
        }
    }
    const b64 = body.join("");
    const binary = atob(b64);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        out[i] = binary.charCodeAt(i);
    }
    return out;
}

/** Compute the SHA-256 fingerprint of the DER bytes, colon-separated. */
function fingerprintHex(der: Uint8Array): string {
    const digest = crypto.sha256(der);
    const hex = toHex(digest);
    const pairs: string[] = [];
    for (let i = 0; i < hex.length; i += 2) {
        pairs.push(hex.slice(i, i + 2));
    }
    return pairs.join(":");
}

/** Parse a PEM or DER certificate and return a summary. */
export function inspectCertificate(pemOrDer: Uint8Array): CertInfo {
    const der = maybePemToDer(pemOrDer) ?? pemOrDer;
    if (der.length === 0) {
        throw new CertParseError("empty certificate input");
    }
    try {
        const cursor = new DerCursor(der);
        const cert = cursor.readTlv();
        if (cert.tag !== TAG_SEQUENCE) {
            throw new CertParseError(`expected SEQUENCE, got 0x${cert.tag.toString(16)}`);
        }
        const tbsCursor = new DerCursor(cert.content);
        const tbsTlv = tbsCursor.readTlv();
        if (tbsTlv.tag !== TAG_SEQUENCE) {
            throw new CertParseError("malformed TBSCertificate");
        }
        const summary = parseTbs(tbsTlv.content);
        return { ...summary, fingerprintSha256: fingerprintHex(der) };
    } catch (err) {
        if (err instanceof CertParseError) {
            throw err;
        }
        const cause = err instanceof Error ? err : undefined;
        const message = `failed to parse certificate: ${err instanceof Error ? err.message : String(err)}`;
        throw new CertParseError(message, cause === undefined ? undefined : { cause });
    }
}
