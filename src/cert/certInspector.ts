/**
 * Certificate inspector — parse PEM/DER X.509 certificates into a summary.
 *
 * Self-contained ASN.1 decoder: walks the TBSCertificate, extracting subject,
 * issuer, validity, SAN, and computing the SHA-256 fingerprint over the whole
 * DER blob. Handles the common DER structures produced by modern CAs; throws
 * {@link CertParseError} on anything it cannot interpret.
 */

import { crypto } from "@browsercore/crypto";
import { CertParseError } from "../errors.js";
import type { CertInfo } from "../types.js";
import { toErrorOptions } from "../utils.js";
import { DerCursor, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE, TAG_SET, parseOid, decodeStringTag, parseTime } from "./der.js";

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
    if (cursor.done) {
        return [];
    }
    // The OCTET STRING content is itself a SEQUENCE OF GeneralName.
    const wrapper = cursor.readTlv();
    if (wrapper.tag !== TAG_SEQUENCE) {
        return [];
    }
    const names: string[] = [];
    const inner = new DerCursor(wrapper.content);
    while (!inner.done) {
        const tlv = inner.readTlv();
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
    if (cursor.done) {
        return [];
    }
    // The [3] content is itself a SEQUENCE OF Extension; unwrap that wrapper.
    const seqOf = cursor.readTlv();
    if (seqOf.tag !== TAG_SEQUENCE) {
        return [];
    }
    const extCursor = new DerCursor(seqOf.content);
    while (!extCursor.done) {
        const ext = extCursor.readTlv();
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
        const byte = bytes[i];
        if (byte !== undefined) {
            out += byte.toString(16).padStart(2, "0");
        }
    }
    return out;
}

/** Strip PEM armor and return the DER body, or null if not PEM. */
function maybePemToDer(input: Uint8Array): Uint8Array | null {
    const text = new TextDecoder("ascii", { fatal: false }).decode(input);
    if (!text.includes("-----BEGIN CERTIFICATE-----")) {
        return null;
    }
    const lines = text.split(/\r?\n/u);
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
        const code = binary.codePointAt(i);
        if (code !== undefined) {
            out[i] = code;
        }
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
    try {
        // maybePemToDer() runs atob() internally, which throws a raw DOMException
        // on invalid base64 — keep it inside the try so the catch can convert
        // that into the documented CertParseError contract.
        const der = maybePemToDer(pemOrDer) ?? pemOrDer;
        if (der.length === 0) {
            throw new CertParseError("empty certificate input");
        }
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
        const message = `failed to parse certificate: ${err instanceof Error ? err.message : String(err)}`;
        throw new CertParseError(message, toErrorOptions(err));
    }
}
