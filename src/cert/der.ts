/**
 * Minimal ASN.1 DER decoding toolkit for X.509 certificates.
 *
 * Self-contained: a cursor over a byte buffer plus pure helpers that walk the
 * string-valued and time-valued TBSCertificate fields. The higher-level
 * TBS parsing in `certInspector.ts` consumes these primitives.
 */

import { CertParseError } from "../errors.js";

/** ASN.1 DER tag classes (class + constructed bit live in byte 0). */
const ASN1_UNIVERSAL = 0x00;
const ASN1_CONSTRUCTED = 0x20;

/**
 * Universal tags we care about. Stored as the full tag byte (class + constructed
 * bit + number) so callers can compare directly against the first byte of a TLV.
 */
export const TAG_SEQUENCE = 0x30; // UNIVERSAL | CONSTRUCTED | 0x10
export const TAG_SET = 0x31; // UNIVERSAL | CONSTRUCTED | 0x11
export const TAG_OID = 0x06;
export const TAG_UTF8STRING = 0x0c;
export const TAG_PRINTABLESTRING = 0x13;
export const TAG_IA5STRING = 0x16;
export const TAG_UTCTIME = 0x17;
export const TAG_GENERALIZEDTIME = 0x18;
export const TAG_OCTET_STRING = 0x04;
const TAG_CONTEXT_SPECIFIC = 0x80;

/** A cursor over a DER byte buffer. */
export class DerCursor {
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

    /**
     * Read a single byte, advancing the cursor. Throws {@link CertParseError}
     * with the given message if the cursor is exhausted.
     */
    readByte(message = "unexpected end of DER"): number {
        if (this.done) {
            throw new CertParseError(message);
        }
        const byte = this.buf[this.pos];
        if (byte === undefined) {
            throw new CertParseError(message);
        }
        this.pos++;
        return byte;
    }

    /** Read one ASN.1 TLV: returns tag, constructed flag, and content bytes. */
    readTlv(): { tag: number; constructed: boolean; content: Uint8Array } {
        const startTag = this.readByte();
        const tagClass = startTag & 0xc0;
        const constructed = (startTag & ASN1_CONSTRUCTED) !== 0;
        const tag = startTag;
        if (tagClass !== ASN1_UNIVERSAL && tagClass !== TAG_CONTEXT_SPECIFIC) {
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
        const first = this.readByte("truncated DER length");
        if (first < 0x80) {
            return first;
        }
        const nbytes = first & 0x7f;
        if (nbytes === 0 || nbytes > 4) {
            throw new CertParseError(`unsupported DER length form: 0x${first.toString(16)}`);
        }
        let len = 0;
        for (let i = 0; i < nbytes; i++) {
            len = (len << 8) | this.readByte("truncated DER long-form length");
        }
        return len;
    }
}

/** Parse an OID byte content to dotted form. */
export function parseOid(content: Uint8Array): string {
    const first = content[0];
    if (first === undefined) {
        throw new CertParseError("empty OID");
    }
    const parts: number[] = [Math.floor(first / 40), first % 40];
    let acc = 0;
    for (let i = 1; i < content.length; i++) {
        const b = content[i];
        if (b === undefined) {
            throw new CertParseError("truncated OID");
        }
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
export function decodeStringTag(tag: number, content: Uint8Array): string {
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
export function parseTime(tag: number, content: Uint8Array): Date {
    const s = new TextDecoder().decode(content);
    let year: number;
    let rest: string;
    if (tag === TAG_UTCTIME) {
        // YYMMDDHHMMSSZ
        const yy = Math.trunc(Number(s.slice(0, 2)));
        // RFC 5280 §4.1.2.5: UTCTime cuts over at 1950/2050 to dodge the Y2K
        // ambiguity, so 50–99 means 1950–1999 and 00–49 means 2000–2049.
        year = yy >= 50 ? 1900 + yy : 2000 + yy;
        rest = s.slice(2);
    } else if (tag === TAG_GENERALIZEDTIME) {
        year = Math.trunc(Number(s.slice(0, 4)));
        rest = s.slice(4);
    } else {
        throw new CertParseError(`expected time tag, got 0x${tag.toString(16)}`);
    }
    const month = Math.trunc(Number(rest.slice(0, 2))) - 1;
    const day = Math.trunc(Number(rest.slice(2, 4)));
    const hour = Math.trunc(Number(rest.slice(4, 6)));
    const minute = Math.trunc(Number(rest.slice(6, 8)));
    const second = rest.length >= 10 ? Math.trunc(Number(rest.slice(8, 10))) : 0;
    const tz = rest.at(-1);
    // RFC 5280 §4.1.2.5 mandates that UTCTime/GeneralizedTime in certificates
    // use the Z (GMT) designator. Reject any other trailing form (offset or
    // missing) rather than silently dropping the offset.
    if (tz !== "Z") {
        throw new CertParseError(`certificate time must use 'Z' timezone, got '${tz}'`);
    }
    return new Date(Date.UTC(year, month, day, hour, minute, second));
}
