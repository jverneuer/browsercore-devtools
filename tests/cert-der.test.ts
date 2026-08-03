import { describe, expect, it } from "vitest";
import { DerCursor, parseOid, parseTime, decodeStringTag, TAG_UTCTIME, TAG_GENERALIZEDTIME } from "../src/cert/der.js";
import { CertParseError } from "../src/errors.js";
import { fromHex } from "./_testhelpers.js";

describe("DerCursor", () => {
    it("tracks offset and reports done at end of buffer", () => {
        const c = new DerCursor(new Uint8Array([0x01, 0x02, 0x03]));
        expect(c.offset).toBe(0);
        expect(c.done).toBe(false);
        expect(c.readByte()).toBe(0x01);
        expect(c.offset).toBe(1);
        c.readByte();
        c.readByte();
        expect(c.done).toBe(true);
        expect(c.offset).toBe(3);
    });

    it("readByte throws CertParseError when exhausted (custom message)", () => {
        const c = new DerCursor(new Uint8Array());
        expect(() => c.readByte("ran out")).toThrow(CertParseError);
        expect(() => c.readByte("ran out")).toThrow("ran out");
    });

    it("rewindTo restores a previously observed offset", () => {
        const c = new DerCursor(new Uint8Array([0xaa, 0xbb, 0xcc]));
        c.readByte();
        const mark = c.offset;
        c.readByte();
        expect(c.offset).toBe(2);
        c.rewindTo(mark);
        expect(c.offset).toBe(1);
        expect(c.readByte()).toBe(0xbb);
    });

    it("readTlv parses a TLV and advances past its content", () => {
        // SEQUENCE { OCTET STRING (0x04) of 2 bytes }
        const buf = fromHex("300404 02 abcd".replace(/\s/g, ""));
        const c = new DerCursor(buf);
        const outer = c.readTlv();
        expect(outer.tag).toBe(0x30);
        expect(outer.constructed).toBe(true);
        expect(Array.from(outer.content)).toEqual([0x04, 0x02, 0xab, 0xcd]);
        expect(c.done).toBe(true);
    });

    it("readTlv reports constructed flag false for primitive tags", () => {
        const c = new DerCursor(fromHex("0201 05"));
        const tlv = c.readTlv();
        expect(tlv.tag).toBe(0x02);
        expect(tlv.constructed).toBe(false);
    });

    it("skipTlv consumes one TLV without surfacing it", () => {
        const c = new DerCursor(fromHex("0201 05 0201 07"));
        c.skipTlv();
        expect(c.offset).toBe(3);
        const next = c.readTlv();
        expect(Array.from(next.content)).toEqual([0x07]);
    });
});

describe("parseOid", () => {
    it("decodes a multi-node OID with a long-form sub-identifier", () => {
        // 1.2.840.113549 — the 113549 node is encoded across two continuation bytes.
        // 1.2 -> 0x2a; 840 -> 0x86 0x48; 113549 -> 0x86 0xf7 0x0d
        const oid = parseOid(fromHex("2a864886f70d"));
        expect(oid).toBe("1.2.840.113549");
    });

    it("decodes a simple two-component OID", () => {
        // 2.5 -> 0x55
        expect(parseOid(fromHex("55"))).toBe("2.5");
    });

    it("throws CertParseError on an empty OID", () => {
        expect(() => parseOid(new Uint8Array())).toThrow(CertParseError);
        expect(() => parseOid(new Uint8Array())).toThrow("empty OID");
    });

    it("throws CertParseError when the final sub-identifier is unterminated", () => {
        // 0x8f has the continuation bit set but no follow-up byte -> truncated.
        expect(() => parseOid(fromHex("028f"))).toThrow("truncated OID");
    });
});

describe("parseTime", () => {
    it("parses a UTCTime in year 2000-2049 (YY < 50)", () => {
        const d = parseTime(TAG_UTCTIME, new TextEncoder().encode("260101000000Z"));
        expect(d.toISOString()).toBe("2026-01-01T00:00:00.000Z");
    });

    it("parses a UTCTime in year 1950-1999 (YY >= 50)", () => {
        const d = parseTime(TAG_UTCTIME, new TextEncoder().encode("500101000000Z"));
        expect(d.toISOString()).toBe("1950-01-01T00:00:00.000Z");
    });

    it("parses a UTCTime without seconds (HHMM only)", () => {
        // YYMMDDHHMM Z — the seconds field defaults to 0.
        const d = parseTime(TAG_UTCTIME, new TextEncoder().encode("2601010000Z"));
        expect(d.toISOString()).toBe("2026-01-01T00:00:00.000Z");
    });

    it("parses a GeneralizedTime (YYYYMMDDHHMMSSZ)", () => {
        const d = parseTime(TAG_GENERALIZEDTIME, new TextEncoder().encode("20491231235959Z"));
        expect(d.toISOString()).toBe("2049-12-31T23:59:59.000Z");
    });

    it("throws CertParseError when the tag is neither UTCTime nor GeneralizedTime", () => {
        expect(() => parseTime(0x02, new TextEncoder().encode("260101000000Z"))).toThrow(CertParseError);
        expect(() => parseTime(0x02, new TextEncoder().encode("260101000000Z"))).toThrow(/expected time tag/);
    });

    it("treats a non-Z (offset) timestamp identically to a Z timestamp", () => {
        // Documents current behavior: both branches return Date.UTC(...) unchanged,
        // so a trailing offset is silently dropped. See bug note in the final report.
        const z = parseTime(TAG_UTCTIME, new TextEncoder().encode("260101000000Z"));
        const offset = parseTime(TAG_UTCTIME, new TextEncoder().encode("260101000000+0000"));
        expect(offset.getTime()).toBe(z.getTime());
    });
});

describe("decodeStringTag", () => {
    it("decodes a PrintableString (0x13)", () => {
        expect(decodeStringTag(0x13, new TextEncoder().encode("US"))).toBe("US");
    });

    it("decodes a UTF8String (0x0c) with multibyte content", () => {
        expect(decodeStringTag(0x0c, new TextEncoder().encode("München"))).toBe("München");
    });

    it("decodes an IA5String (0x16)", () => {
        expect(decodeStringTag(0x16, new TextEncoder().encode("user@example.com"))).toBe("user@example.com");
    });

    it("throws CertParseError for an unsupported string tag", () => {
        // INTEGER (0x02) is not a string type.
        expect(() => decodeStringTag(0x02, new Uint8Array())).toThrow(CertParseError);
        expect(() => decodeStringTag(0x02, new Uint8Array())).toThrow(/unsupported string tag/);
    });
});
