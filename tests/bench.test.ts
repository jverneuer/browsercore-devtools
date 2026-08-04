import { describe, expect, it } from "vitest";
import { bytesToHex, compareBytes } from "../src/bench/compare.js";
import { computeJa3, parseClientHello, Ja3ParseError } from "../src/bench/ja3.js";
import { computeJa4, computeJa4Fingerprint, parseJa4ClientHello, Ja4ParseError } from "../src/bench/ja4.js";
import {
    GREASE_VALUES,
    EXT_SNI,
    EXT_SUPPORTED_GROUPS,
    EXT_EC_POINT_FORMATS,
    EXT_ALPN,
    uint16,
    uint24,
    hex4,
    tlsVersionLabel,
    readSupportedGroups,
    readEcPointFormats,
    readAlpnProtocols,
} from "../src/bench/ja4-reader.js";

/** Build a minimal valid ClientHello (bare handshake, no record wrapper). */
function minimalClientHello(): Uint8Array {
    const version = [0x03, 0x04]; // TLS 1.3
    const random = new Uint8Array(32);
    const sessionIdLen = [0x00];
    const cipherSuites = [0x00, 0x02, 0x13, 0x01]; // length(2) + TLS_AES_128_GCM_SHA256
    const compression = [0x01, 0x00]; // length(1) + null
    const extensions = [0x00, 0x00]; // length(2) — no extensions
    const body = [
        ...version,
        ...random,
        ...sessionIdLen,
        ...cipherSuites,
        ...compression,
        ...extensions,
    ];
    const handshakeLen = [(body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff];
    return new Uint8Array([0x01, ...handshakeLen, ...body]);
}

/** Wrap a bare handshake body in a TLS record. */
function wrapInRecord(handshake: Uint8Array): Uint8Array {
    return new Uint8Array([0x16, 0x03, 0x03, (handshake.length >> 8) & 0xff, handshake.length & 0xff, ...handshake]);
}

describe("compare", () => {
    it("bytesToHex formats bytes as lowercase hex", () => {
        expect(bytesToHex(new Uint8Array([0x00, 0x0a, 0xff]))).toBe("000aff");
    });

    it("compareBytes reports equal for identical arrays", () => {
        const a = new Uint8Array([0x01, 0x02, 0x03]);
        const result = compareBytes(a, a);
        expect(result.matches).toBe(true);
        expect(result.divergenceByteIndex).toBeUndefined();
        expect(result.message).toBe("equal");
    });

    it("compareBytes reports length mismatch", () => {
        const a = new Uint8Array([0x01, 0x02]);
        const b = new Uint8Array([0x01, 0x02, 0x03]);
        const result = compareBytes(a, b);
        expect(result.matches).toBe(false);
        expect(result.divergenceByteIndex).toBe(2);
        expect(result.message).toContain("Length mismatch");
    });

    it("compareBytes reports first divergence index", () => {
        const a = new Uint8Array([0x01, 0x02, 0x03]);
        const b = new Uint8Array([0x01, 0xff, 0x03]);
        const result = compareBytes(a, b);
        expect(result.matches).toBe(false);
        expect(result.divergenceByteIndex).toBe(1);
        expect(result.message).toContain("Byte 1");
    });
});

describe("ja3", () => {
    it("parses a minimal bare ClientHello", () => {
        const hello = minimalClientHello();
        const segments = parseClientHello(hello);
        expect(segments.version).toBe("772"); // 0x0304 = 772
        expect(segments.ciphers).toBe("4865"); // 0x1301 = 4865
        expect(segments.extensions).toBe("");
        expect(segments.supportedGroups).toBe("");
        expect(segments.ecPointFormats).toBe("");
    });

    it("parses a record-wrapped ClientHello", () => {
        const hello = wrapInRecord(minimalClientHello());
        const segments = parseClientHello(hello);
        expect(segments.version).toBe("772"); // 0x0304 = 772
    });

    it("computes a stable JA3 digest", () => {
        const hello = minimalClientHello();
        const digest = computeJa3(hello);
        expect(digest).toMatch(/^[0-9a-f]{32}$/);
    });

    it("throws Ja3ParseError on a buffer that is neither TLS record nor handshake", () => {
        const bad = new Uint8Array([0x00, 0x00, 0x00, 0x00]);
        expect(() => parseClientHello(bad)).toThrow(Ja3ParseError);
        expect(() => parseClientHello(bad)).toThrow(/Not a TLS record/);
    });

    it("throws Ja3ParseError on a truncated TLS record", () => {
        const bad = new Uint8Array([0x16, 0x03]); // too short for a record
        expect(() => parseClientHello(bad)).toThrow(Ja3ParseError);
        expect(() => parseClientHello(bad)).toThrow(/TLS record too short/);
    });

    it("throws Ja3ParseError when record+0 is not a ClientHello", () => {
        // TLS record wrapper with wrong handshake type
        const inner = minimalClientHello();
        const bad = new Uint8Array([0x16, 0x03, 0x03, (inner.length >> 8) & 0xff, inner.length & 0xff, 0x02, ...inner.slice(1)]);
        expect(() => parseClientHello(bad)).toThrow(Ja3ParseError);
        expect(() => parseClientHello(bad)).toThrow(/Expected ClientHello/);
    });

    it("throws Ja3ParseError when handshake length exceeds available bytes (bare)", () => {
        const hello = minimalClientHello();
        const truncated = hello.slice(0, 10);
        expect(() => parseClientHello(truncated)).toThrow(Ja3ParseError);
    });

    it("throws Ja3ParseError on truncated session id", () => {
        // Buffer ends right at the session id length byte position.
        const version = [0x03, 0x04];
        const random = new Uint8Array(32);
        const body = [...version, ...random]; // 34 bytes
        const handshakeLen = [(body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff];
        const buf = new Uint8Array([0x01, ...handshakeLen, ...body]); // 38 bytes total
        expect(() => parseClientHello(buf)).toThrow(Ja3ParseError);
        expect(() => parseClientHello(buf)).toThrow(/session id/);
    });

    it("throws Ja3ParseError on truncated compression methods", () => {
        // Body ends right before the compression methods length byte.
        const version = [0x03, 0x04];
        const random = new Uint8Array(32);
        const sessionIdLen = [0x00];
        const cipherSuites = [0x00, 0x02, 0x13, 0x01];
        const body = [...version, ...random, ...sessionIdLen, ...cipherSuites];
        const handshakeLen = [(body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff];
        const buf = new Uint8Array([0x01, ...handshakeLen, ...body]);
        expect(() => parseClientHello(buf)).toThrow(Ja3ParseError);
        expect(() => parseClientHello(buf)).toThrow(/compression methods/);
    });

    it("throws Ja3ParseError on truncated ec_point_formats list", () => {
        // Build a ClientHello with an ec_point_formats extension that claims more bytes than available
        const version = [0x03, 0x04];
        const random = new Uint8Array(32);
        const sessionIdLen = [0x00];
        const cipherSuites = [0x00, 0x02, 0x13, 0x01];
        const compression = [0x01, 0x00];
        // extension: type=0x000b (ec_point_formats), length=0x0004, list length=0x04 (but only 1 byte follows)
        const extType = [0x00, 0x0b];
        const extLen = [0x00, 0x04];
        const ecBody = [0x04, 0x00]; // list length 4, only 1 byte
        const extensionsLen = [0x00, extType.length + extLen.length + ecBody.length];
        const body = [
            ...version,
            ...random,
            ...sessionIdLen,
            ...cipherSuites,
            ...compression,
            ...extensionsLen,
            ...extType,
            ...extLen,
            ...ecBody,
        ];
        const handshakeLen = [(body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff];
        const buf = new Uint8Array([0x01, ...handshakeLen, ...body]);
        expect(() => parseClientHello(buf)).toThrow(Ja3ParseError);
    });

    it("throws Ja3ParseError via readInt24 out of bounds", () => {
        // Truncate the buffer right where readInt24 would read (bare handshake, offset 1)
        const buf = new Uint8Array([0x01, 0x00]); // only 2 bytes, readInt24 needs 3
        expect(() => parseClientHello(buf)).toThrow(Ja3ParseError);
    });

    it("throws Ja3ParseError via uint16 out of bounds", () => {
        // Bare handshake: after version(2) + random(32) + sessionIdLen(1) = 35 bytes consumed,
        // then uint16 for cipherSuitesLen at pos 39. Truncate so pos 39-40 is out of bounds.
        const version = [0x03, 0x04];
        const random = new Uint8Array(32);
        const sessionIdLen = [0x00];
        const body = [...version, ...random, ...sessionIdLen]; // 35 bytes
        // Set handshakeLen large enough to pass initial check but truncate buffer before cipherSuitesLen
        const handshakeLen = [0x00, 0x00, 0x20]; // claims 32 bytes
        const buf = new Uint8Array([0x01, ...handshakeLen, ...body]); // 39 bytes total
        expect(() => parseClientHello(buf)).toThrow(Ja3ParseError);
    });

    it("throws Ja3ParseError when bare handshake length exceeds available", () => {
        const version = [0x03, 0x04];
        const random = new Uint8Array(32);
        const sessionIdLen = [0x00];
        const body = [...version, ...random, ...sessionIdLen]; // 35 bytes
        const handshakeLen = [0x00, 0x01, 0x00]; // claims 256 bytes, but only 35 available
        const buf = new Uint8Array([0x01, ...handshakeLen, ...body]);
        expect(() => parseClientHello(buf)).toThrow(Ja3ParseError);
        expect(() => parseClientHello(buf)).toThrow(/Handshake length/);
    });

    it("returns no extensions when pos + 2 > end after compression methods", () => {
        const version = [0x03, 0x04];
        const random = new Uint8Array(32);
        const sessionIdLen = [0x00];
        const cipherSuites = [0x00, 0x02, 0x13, 0x01];
        const compression = [0x01, 0x00];
        const body = [...version, ...random, ...sessionIdLen, ...cipherSuites, ...compression];
        const handshakeLen = [(body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff];
        const buf = new Uint8Array([0x01, ...handshakeLen, ...body]);
        const segments = parseClientHello(buf);
        expect(segments.extensions).toBe("");
        expect(segments.supportedGroups).toBe("");
        expect(segments.ecPointFormats).toBe("");
    });

    it("throws Ja3ParseError when record wrapper handshake length exceeds available", () => {
        // Record wrapper: 0x16 0x03 0x03 + uint16 length, then handshake type 0x01 + uint24 length
        // Set handshakeLen large so it exceeds available bytes
        const buf = new Uint8Array([0x16, 0x03, 0x03, 0x00, 0x20, 0x01, 0x00, 0x01, 0x00, 0x03, 0x04]);
        expect(() => parseClientHello(buf)).toThrow(Ja3ParseError);
        expect(() => parseClientHello(buf)).toThrow(/Handshake length/);
    });

    it("throws Ja3ParseError when ec_point_formats listLen byte is out of bounds", () => {
        const version = [0x03, 0x04];
        const random = new Uint8Array(32);
        const sessionIdLen = [0x00];
        const cipherSuites = [0x00, 0x02, 0x13, 0x01];
        const compression = [0x01, 0x00];
        // ec_point_formats(11) extension: type(2) + length(2) + body
        // The body starts with listLen(1). Make the extension end right before listLen.
        const extType = [0x00, 0x0b];
        const extLen = [0x00, 0x01]; // claims 1 byte of body
        const extensionsLen = [0x00, extType.length + extLen.length]; // no room for body
        const body = [
            ...version,
            ...random,
            ...sessionIdLen,
            ...cipherSuites,
            ...compression,
            ...extensionsLen,
            ...extType,
            ...extLen,
        ];
        const handshakeLen = [(body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff];
        const buf = new Uint8Array([0x01, ...handshakeLen, ...body]);
        expect(() => parseClientHello(buf)).toThrow(Ja3ParseError);
    });

    it("throws Ja3ParseError when readUint16List goes out of bounds (supported_groups)", () => {
        const version = [0x03, 0x04];
        const random = new Uint8Array(32);
        const sessionIdLen = [0x00];
        const cipherSuites = [0x00, 0x02, 0x13, 0x01];
        const compression = [0x01, 0x00];
        // supported_groups(10): type(2) + length(2) + listLen(2) + groups
        // Claim listLen = 0x0008 (8 bytes = 4 groups) but only provide 2 bytes
        const extType = [0x00, 0x0a];
        const extLen = [0x00, 0x0a]; // claims 10 bytes of body
        const sgBody = [0x00, 0x08, 0x00, 0x1d]; // listLen=8, but only 2 bytes of groups
        const extensionsLen = [0x00, extType.length + extLen.length + sgBody.length];
        const body = [
            ...version,
            ...random,
            ...sessionIdLen,
            ...cipherSuites,
            ...compression,
            ...extensionsLen,
            ...extType,
            ...extLen,
            ...sgBody,
        ];
        const handshakeLen = [(body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff];
        const buf = new Uint8Array([0x01, ...handshakeLen, ...body]);
        expect(() => parseClientHello(buf)).toThrow(Ja3ParseError);
        expect(() => parseClientHello(buf)).toThrow(/readUint16List out of bounds/);
    });
});

describe("ja4", () => {
    it("parses a minimal bare ClientHello", () => {
        const hello = minimalClientHello();
        const parsed = parseJa4ClientHello(hello);
        expect(parsed.tlsVersion).toBe("13");
        expect(parsed.sniPresent).toBe(false);
        expect(parsed.cipherSuites.length).toBeGreaterThan(0);
    });

    it("computes a canonical JA4 tag", () => {
        const hello = minimalClientHello();
        const tag = computeJa4(hello);
        // JA4_a = t{ciphers:02d}{exts:02d}{sni_flag}{version}{alpn}
        expect(tag).toMatch(/^t\d{4}[a-z]\d{2}[0-9a]{2}_[0-9a-f]{12}_[0-9a-f]{12}_[0-9a-f]{12}$/);
    });

    it("computeJa4Fingerprint returns all four parts", () => {
        const hello = minimalClientHello();
        const fp = computeJa4Fingerprint(hello);
        expect(fp.a).toMatch(/^t\d{4}/);
        expect(fp.b).toMatch(/^[0-9a-f]{12}$/);
        expect(fp.c).toMatch(/^[0-9a-f]{12}$/);
        expect(fp.f).toMatch(/^[0-9a-f]{12}$/);
        expect(fp.tag).toBe(`${fp.a}_${fp.b}_${fp.c}_${fp.f}`);
    });

    it("parses a record-wrapped ClientHello", () => {
        const hello = wrapInRecord(minimalClientHello());
        const parsed = parseJa4ClientHello(hello);
        expect(parsed.tlsVersion).toBe("13");
    });

    it("throws Ja4ParseError on empty buffer", () => {
        expect(() => parseJa4ClientHello(new Uint8Array(0))).toThrow(Ja4ParseError);
        expect(() => parseJa4ClientHello(new Uint8Array(0))).toThrow(/empty/);
    });

    it("throws Ja4ParseError on a buffer that is neither TLS record nor handshake", () => {
        const bad = new Uint8Array([0x00, 0x00, 0x00, 0x00]);
        expect(() => parseJa4ClientHello(bad)).toThrow(Ja4ParseError);
        expect(() => parseJa4ClientHello(bad)).toThrow(/Not a TLS record/);
    });

    it("throws Ja4ParseError on a truncated TLS record", () => {
        const bad = new Uint8Array([0x16, 0x03]);
        expect(() => parseJa4ClientHello(bad)).toThrow(Ja4ParseError);
        expect(() => parseJa4ClientHello(bad)).toThrow(/TLS record too short/);
    });

    it("throws Ja4ParseError when record+0 is not a ClientHello", () => {
        const inner = minimalClientHello();
        const bad = new Uint8Array([0x16, 0x03, 0x03, (inner.length >> 8) & 0xff, inner.length & 0xff, 0x02, ...inner.slice(1)]);
        expect(() => parseJa4ClientHello(bad)).toThrow(Ja4ParseError);
        expect(() => parseJa4ClientHello(bad)).toThrow(/Expected ClientHello/);
    });

    it("throws Ja4ParseError on a truncated bare ClientHello", () => {
        const bad = new Uint8Array([0x01, 0x00]); // too short for bare
        expect(() => parseJa4ClientHello(bad)).toThrow(Ja4ParseError);
        expect(() => parseJa4ClientHello(bad)).toThrow(/Bare ClientHello too short/);
    });

    it("throws Ja4ParseError when handshake length exceeds available bytes", () => {
        const hello = minimalClientHello();
        const truncated = hello.slice(0, 10);
        expect(() => parseJa4ClientHello(truncated)).toThrow(Ja4ParseError);
    });

    it("throws Ja4ParseError on truncated session id", () => {
        // Buffer ends right at the session id length byte position.
        const version = [0x03, 0x04];
        const random = new Uint8Array(32);
        const body = [...version, ...random]; // 34 bytes
        const handshakeLen = [(body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff];
        const buf = new Uint8Array([0x01, ...handshakeLen, ...body]); // 38 bytes total
        expect(() => parseJa4ClientHello(buf)).toThrow(Ja4ParseError);
        expect(() => parseJa4ClientHello(buf)).toThrow(/session id/);
    });

    it("throws Ja4ParseError on truncated cipher suites", () => {
        // Buffer ends right before the cipher suites length byte.
        const version = [0x03, 0x04];
        const random = new Uint8Array(32);
        const sessionIdLen = [0x00];
        const body = [...version, ...random, ...sessionIdLen]; // 35 bytes
        const handshakeLen = [(body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff];
        const buf = new Uint8Array([0x01, ...handshakeLen, ...body]); // 39 bytes total
        expect(() => parseJa4ClientHello(buf)).toThrow(Ja4ParseError);
        expect(() => parseJa4ClientHello(buf)).toThrow(/cipher suites/);
    });

    it("throws Ja4ParseError on truncated compression methods", () => {
        // Body ends right before the compression methods length byte.
        const version = [0x03, 0x04];
        const random = new Uint8Array(32);
        const sessionIdLen = [0x00];
        const cipherSuites = [0x00, 0x02, 0x13, 0x01];
        const body = [...version, ...random, ...sessionIdLen, ...cipherSuites];
        const handshakeLen = [(body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff];
        const buf = new Uint8Array([0x01, ...handshakeLen, ...body]);
        expect(() => parseJa4ClientHello(buf)).toThrow(Ja4ParseError);
        expect(() => parseJa4ClientHello(buf)).toThrow(/compression methods/);
    });

    it("returns zeroed JA4_b and JA4_c when no ciphers/extensions after GREASE filtering", () => {
        // Build a ClientHello with only GREASE cipher suites
        const version = [0x03, 0x04];
        const random = new Uint8Array(32);
        const sessionIdLen = [0x00];
        // Only GREASE cipher suite 0x0a0a
        const cipherSuites = [0x00, 0x02, 0x0a, 0x0a];
        const compression = [0x01, 0x00];
        const extensions = [0x00, 0x00];
        const body = [
            ...version,
            ...random,
            ...sessionIdLen,
            ...cipherSuites,
            ...compression,
            ...extensions,
        ];
        const handshakeLen = [(body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff];
        const buf = new Uint8Array([0x01, ...handshakeLen, ...body]);
        const fp = computeJa4Fingerprint(buf);
        expect(fp.b).toBe("000000000000");
        expect(fp.c).toBe("000000000000");
    });

    it("detects SNI presence and sets the sni_flag in JA4_a", () => {
        // Build a ClientHello with an SNI extension (type 0x0000)
        const version = [0x03, 0x04];
        const random = new Uint8Array(32);
        const sessionIdLen = [0x00];
        const cipherSuites = [0x00, 0x02, 0x13, 0x01];
        const compression = [0x01, 0x00];
        // SNI extension: type=0x0000, length=0x0005, then 5 bytes of SNI data
        const sniExt = [0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00];
        const extensionsLen = [0x00, sniExt.length];
        const body = [
            ...version,
            ...random,
            ...sessionIdLen,
            ...cipherSuites,
            ...compression,
            ...extensionsLen,
            ...sniExt,
        ];
        const handshakeLen = [(body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff];
        const buf = new Uint8Array([0x01, ...handshakeLen, ...body]);
        const parsed = parseJa4ClientHello(buf);
        expect(parsed.sniPresent).toBe(true);
        const fp = computeJa4Fingerprint(buf);
        expect(fp.a).toContain("d"); // sni_flag = "d" when SNI present
    });

    it("parses a ClientHello with a supported_groups extension", () => {
        const version = [0x03, 0x04];
        const random = new Uint8Array(32);
        const sessionIdLen = [0x00];
        const cipherSuites = [0x00, 0x02, 0x13, 0x01];
        const compression = [0x01, 0x00];
        // supported_groups(10): length=0x0004, list length=0x0002, one group 0x001d (x25519)
        const sgExt = [0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d];
        const extensionsLen = [0x00, sgExt.length];
        const body = [
            ...version,
            ...random,
            ...sessionIdLen,
            ...cipherSuites,
            ...compression,
            ...extensionsLen,
            ...sgExt,
        ];
        const handshakeLen = [(body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff];
        const buf = new Uint8Array([0x01, ...handshakeLen, ...body]);
        const parsed = parseJa4ClientHello(buf);
        expect(parsed.supportedGroups).toEqual([0x001d]);
    });

    it("parses a ClientHello with an ALPN extension", () => {
        const version = [0x03, 0x04];
        const random = new Uint8Array(32);
        const sessionIdLen = [0x00];
        const cipherSuites = [0x00, 0x02, 0x13, 0x01];
        const compression = [0x01, 0x00];
        // ALPN(16): length=0x0005, list length=0x0003, then "h2" (len 2) — wait, list length includes the per-protocol length bytes
        // ALN list: length(2) + (len(1) + "h2"(2)) = 5 bytes
        const alpnExt = [0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x32];
        const extensionsLen = [0x00, alpnExt.length];
        const body = [
            ...version,
            ...random,
            ...sessionIdLen,
            ...cipherSuites,
            ...compression,
            ...extensionsLen,
            ...alpnExt,
        ];
        const handshakeLen = [(body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff];
        const buf = new Uint8Array([0x01, ...handshakeLen, ...body]);
        const parsed = parseJa4ClientHello(buf);
        expect(parsed.alpnRaw).toBe("h2");
        // ALPN code should be first char of first + first char of last
        const fp = computeJa4Fingerprint(buf);
        expect(fp.a).toMatch(/hh$/);
    });

    it("skips GREASE extension types when building the extension list", () => {
        const version = [0x03, 0x04];
        const random = new Uint8Array(32);
        const sessionIdLen = [0x00];
        const cipherSuites = [0x00, 0x02, 0x13, 0x01];
        const compression = [0x01, 0x00];
        // GREASE extension: type=0x0a0a, length=0x0000
        const greaseExt = [0x0a, 0x0a, 0x00, 0x00];
        const extensionsLen = [0x00, greaseExt.length];
        const body = [
            ...version,
            ...random,
            ...sessionIdLen,
            ...cipherSuites,
            ...compression,
            ...extensionsLen,
            ...greaseExt,
        ];
        const handshakeLen = [(body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff];
        const buf = new Uint8Array([0x01, ...handshakeLen, ...body]);
        const parsed = parseJa4ClientHello(buf);
        expect(parsed.extensions).not.toContain(0x0a0a);
        expect(parsed.extensions).toEqual([]);
    });

    it("throws Ja4ParseError when bare ClientHello is too short for version", () => {
        // Bare handshake where end = pos (handshakeLen = 0), so pos + 2 > end
        const version = [0x03, 0x04];
        const random = new Uint8Array(32);
        const sessionIdLen = [0x00];
        const cipherSuites = [0x00, 0x02, 0x13, 0x01];
        const compression = [0x01, 0x00];
        const body = [...version, ...random, ...sessionIdLen, ...cipherSuites, ...compression];
        // Set handshakeLen = 0 so end = pos immediately
        const handshakeLen = [0x00, 0x00, 0x00];
        const buf = new Uint8Array([0x01, ...handshakeLen, ...body]);
        expect(() => parseJa4ClientHello(buf)).toThrow(Ja4ParseError);
        expect(() => parseJa4ClientHello(buf)).toThrow(/version/);
    });

    it("throws Ja4ParseError when pos exceeds end before session id (truncated random)", () => {
        const version = [0x03, 0x04];
        const random = new Uint8Array(32);
        const sessionIdLen = [0x00];
        const cipherSuites = [0x00, 0x02, 0x13, 0x01];
        const compression = [0x01, 0x00];
        const body = [...version, ...random, ...sessionIdLen, ...cipherSuites, ...compression];
        // Set handshakeLen = 2 so end = pos + 2, but we need pos > end after random (pos advances 34 bytes)
        const handshakeLen = [0x00, 0x00, 0x02];
        const buf = new Uint8Array([0x01, ...handshakeLen, ...body]);
        expect(() => parseJa4ClientHello(buf)).toThrow(Ja4ParseError);
        expect(() => parseJa4ClientHello(buf)).toThrow(/session id/);
    });

    it("returns no extensions when pos + 2 > end after compression methods", () => {
        const version = [0x03, 0x04];
        const random = new Uint8Array(32);
        const sessionIdLen = [0x00];
        const cipherSuites = [0x00, 0x02, 0x13, 0x01];
        const compression = [0x01, 0x00];
        const body = [...version, ...random, ...sessionIdLen, ...cipherSuites, ...compression];
        // handshakeLen = body.length so end = pos + body.length — but after reading compression, pos = end, so pos + 2 > end
        const handshakeLen = [(body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff];
        const buf = new Uint8Array([0x01, ...handshakeLen, ...body]);
        const parsed = parseJa4ClientHello(buf);
        expect(parsed.extensions).toEqual([]);
        expect(parsed.supportedGroups).toEqual([]);
        expect(parsed.ecPointFormats).toEqual([]);
    });

    it("throws Ja4ParseError when cipher suites extend past end", () => {
        const version = [0x03, 0x04];
        const random = new Uint8Array(32);
        const sessionIdLen = [0x00];
        const cipherSuites = [0x00, 0x02, 0x13, 0x01];
        const compression = [0x01, 0x00];
        const body = [...version, ...random, ...sessionIdLen, ...cipherSuites, ...compression];
        // After version+random+sessionId: pos = 4+2+32+1 = 39. pos + cipherSuitesLen(2) > end means end < 41, so handshakeLen < 37
        const handshakeLen = [0x00, 0x00, 36]; // end = 40, pos(39) + 2 > 40 ✓
        const buf = new Uint8Array([0x01, ...handshakeLen, ...body]);
        expect(() => parseJa4ClientHello(buf)).toThrow(Ja4ParseError);
        expect(() => parseJa4ClientHello(buf)).toThrow(/cipher suites/);
    });

    it("throws Ja4ParseError via readInt24 out of bounds in record wrapper", () => {
        // Record wrapper: 0x16 0x03 0x03, then uint16 length. Truncate before handshake type.
        const buf = new Uint8Array([0x16, 0x03, 0x03, 0x00, 0x20, 0x01, 0x00]); // only 7 bytes
        expect(() => parseJa4ClientHello(buf)).toThrow(Ja4ParseError);
    });

    it("does not push GREASE extensions but still parses non-GREASE extensions", () => {
        const version = [0x03, 0x04];
        const random = new Uint8Array(32);
        const sessionIdLen = [0x00];
        const cipherSuites = [0x00, 0x02, 0x13, 0x01];
        const compression = [0x01, 0x00];
        // Two extensions: GREASE (0x0a0a) and SNI (0x0000)
        const greaseExt = [0x0a, 0x0a, 0x00, 0x00];
        const sniExt = [0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00];
        const allExts = [...greaseExt, ...sniExt];
        const extensionsLen = [0x00, allExts.length];
        const body = [
            ...version,
            ...random,
            ...sessionIdLen,
            ...cipherSuites,
            ...compression,
            ...extensionsLen,
            ...allExts,
        ];
        const handshakeLen = [(body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff];
        const buf = new Uint8Array([0x01, ...handshakeLen, ...body]);
        const parsed = parseJa4ClientHello(buf);
        expect(parsed.extensions).not.toContain(0x0a0a);
        expect(parsed.extensions).toContain(0x0000);
    });

    it("parses supported_groups even when extLen is exactly 4", () => {
        const version = [0x03, 0x04];
        const random = new Uint8Array(32);
        const sessionIdLen = [0x00];
        const cipherSuites = [0x00, 0x02, 0x13, 0x01];
        const compression = [0x01, 0x00];
        // supported_groups(10) with extLen = 4: listLen(2) + 1 group(2) = 4
        const sgExt = [0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d];
        const extensionsLen = [0x00, sgExt.length];
        const body = [
            ...version,
            ...random,
            ...sessionIdLen,
            ...cipherSuites,
            ...compression,
            ...extensionsLen,
            ...sgExt,
        ];
        const handshakeLen = [(body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff];
        const buf = new Uint8Array([0x01, ...handshakeLen, ...body]);
        const parsed = parseJa4ClientHello(buf);
        expect(parsed.supportedGroups).toEqual([0x001d]);
    });

    it("does not read ec_point_formats when extLen is 0", () => {
        const version = [0x03, 0x04];
        const random = new Uint8Array(32);
        const sessionIdLen = [0x00];
        const cipherSuites = [0x00, 0x02, 0x13, 0x01];
        const compression = [0x01, 0x00];
        // ec_point_formats(11) with extLen = 0
        const ecExt = [0x00, 0x0b, 0x00, 0x00];
        const extensionsLen = [0x00, ecExt.length];
        const body = [
            ...version,
            ...random,
            ...sessionIdLen,
            ...cipherSuites,
            ...compression,
            ...extensionsLen,
            ...ecExt,
        ];
        const handshakeLen = [(body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff];
        const buf = new Uint8Array([0x01, ...handshakeLen, ...body]);
        const parsed = parseJa4ClientHello(buf);
        expect(parsed.ecPointFormats).toEqual([]);
    });

    it("does not read ALPN when extLen < 2", () => {
        const version = [0x03, 0x04];
        const random = new Uint8Array(32);
        const sessionIdLen = [0x00];
        const cipherSuites = [0x00, 0x02, 0x13, 0x01];
        const compression = [0x01, 0x00];
        // ALPN(16) with extLen = 1 (< 2, so ALPN is skipped)
        const alpnExt = [0x00, 0x10, 0x00, 0x01, 0x00];
        const extensionsLen = [0x00, alpnExt.length];
        const body = [
            ...version,
            ...random,
            ...sessionIdLen,
            ...cipherSuites,
            ...compression,
            ...extensionsLen,
            ...alpnExt,
        ];
        const handshakeLen = [(body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff];
        const buf = new Uint8Array([0x01, ...handshakeLen, ...body]);
        const parsed = parseJa4ClientHello(buf);
        expect(parsed.alpnRaw).toBe("");
    });

    it("throws Ja4ParseError when record wrapper handshake length exceeds available", () => {
        // Record wrapper: 0x16 0x03 0x03 + uint16 length, then 0x01 + uint24 length
        // Set handshakeLen large so it exceeds available
        const buf = new Uint8Array([0x16, 0x03, 0x03, 0x00, 0x20, 0x01, 0x00, 0x01, 0x00, 0x03, 0x04]);
        expect(() => parseJa4ClientHello(buf)).toThrow(Ja4ParseError);
        expect(() => parseJa4ClientHello(buf)).toThrow(/Handshake length/);
    });

    it("does not read supported_groups when extLen < 4", () => {
        const version = [0x03, 0x04];
        const random = new Uint8Array(32);
        const sessionIdLen = [0x00];
        const cipherSuites = [0x00, 0x02, 0x13, 0x01];
        const compression = [0x01, 0x00];
        // supported_groups(10) with extLen = 2 (< 4, so groups are skipped)
        // extLen 2 = just the listLen(2) with 0 groups
        const sgExt = [0x00, 0x0a, 0x00, 0x02, 0x00, 0x00];
        const extensionsLen = [0x00, sgExt.length];
        const body = [
            ...version,
            ...random,
            ...sessionIdLen,
            ...cipherSuites,
            ...compression,
            ...extensionsLen,
            ...sgExt,
        ];
        const handshakeLen = [(body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff];
        const buf = new Uint8Array([0x01, ...handshakeLen, ...body]);
        const parsed = parseJa4ClientHello(buf);
        expect(parsed.supportedGroups).toEqual([]);
    });

    it("handles ALPN with a single protocol", () => {
        // When there's only one ALPN protocol, first == last
        const version = [0x03, 0x04];
        const random = new Uint8Array(32);
        const sessionIdLen = [0x00];
        const cipherSuites = [0x00, 0x02, 0x13, 0x01];
        const compression = [0x01, 0x00];
        // ALPN(16): length=0x0005, list length=0x0003, then "h2" (len 2)
        const alpnExt = [0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x32];
        const extensionsLen = [0x00, alpnExt.length];
        const body = [
            ...version,
            ...random,
            ...sessionIdLen,
            ...cipherSuites,
            ...compression,
            ...extensionsLen,
            ...alpnExt,
        ];
        const handshakeLen = [(body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff];
        const buf = new Uint8Array([0x01, ...handshakeLen, ...body]);
        const parsed = parseJa4ClientHello(buf);
        expect(parsed.alpnRaw).toBe("h2");
        const fp = computeJa4Fingerprint(buf);
        expect(fp.a).toMatch(/hh$/); // first char of first + first char of last = "h" + "h"
    });
});

describe("ja4-reader", () => {
    it("GREASE_VALUES contains the RFC 8701 reserved values", () => {
        expect(GREASE_VALUES.has(0x0a0a)).toBe(true);
        expect(GREASE_VALUES.has(0x1a1a)).toBe(true);
        expect(GREASE_VALUES.has(0xfafa)).toBe(true);
        expect(GREASE_VALUES.has(0x0000)).toBe(false);
    });

    it("uint16 reads big-endian uint16", () => {
        const buf = new Uint8Array([0x13, 0x01]);
        expect(uint16(buf, 0)).toBe(0x1301);
    });

    it("uint16 throws on out-of-bounds read", () => {
        const buf = new Uint8Array([0x13]);
        expect(() => uint16(buf, 0)).toThrow(Ja4ParseError);
    });

    it("uint24 reads 24-bit big-endian integer", () => {
        const buf = new Uint8Array([0x00, 0x01, 0x02]);
        expect(uint24(buf, 0)).toBe(0x000102);
    });

    it("uint24 throws on out-of-bounds read", () => {
        const buf = new Uint8Array([0x00, 0x01]);
        expect(() => uint24(buf, 0)).toThrow(Ja4ParseError);
    });

    it("hex4 formats as 4-char lowercase hex", () => {
        expect(hex4(0x0000)).toBe("0000");
        expect(hex4(0x1301)).toBe("1301");
        expect(hex4(0xff)).toBe("00ff");
    });

    it("tlsVersionLabel maps known TLS versions", () => {
        expect(tlsVersionLabel(0x0304)).toBe("13");
        expect(tlsVersionLabel(0x0303)).toBe("12");
        expect(tlsVersionLabel(0x0301)).toBe("10");
    });

    it("tlsVersionLabel falls back to hex for unknown versions", () => {
        expect(tlsVersionLabel(0x0305)).toBe("305");
        expect(tlsVersionLabel(0x0000)).toBe("00");
    });

    it("readSupportedGroups reads non-GREASE groups", () => {
        // list length 4, then two groups: 0x001d (x25519) and 0x0a0a (GREASE)
        const buf = new Uint8Array([0x00, 0x04, 0x00, 0x1d, 0x0a, 0x0a]);
        const groups = readSupportedGroups(buf, 0);
        expect(groups).toEqual([0x001d]);
    });

    it("readSupportedGroups throws on truncation", () => {
        const buf = new Uint8Array([0x00, 0x04, 0x00]); // claims 4 bytes but only 1 follows
        expect(() => readSupportedGroups(buf, 0)).toThrow(Ja4ParseError);
    });

    it("readEcPointFormats reads formats", () => {
        const buf = new Uint8Array([0x03, 0x00, 0x01, 0x02]); // length 3, three formats
        const formats = readEcPointFormats(buf, 0);
        expect(formats).toEqual([0x00, 0x01, 0x02]);
    });

    it("readEcPointFormats throws on truncation", () => {
        const buf = new Uint8Array([0x03, 0x00]); // claims 3 but only 1 follows
        expect(() => readEcPointFormats(buf, 0)).toThrow(Ja4ParseError);
    });

    it("readAlpnProtocols reads protocol list", () => {
        // list length 6, then "h2" (len 2) + "http/1.1" (len 8)
        const h2 = [0x02, 0x68, 0x32];
        const http11 = [0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31];
        const listLen = h2.length + http11.length;
        const buf = new Uint8Array([(listLen >> 8) & 0xff, listLen & 0xff, ...h2, ...http11]);
        const result = readAlpnProtocols(buf, 0);
        expect(result).toBe("h2,http/1.1");
    });

    it("readAlpnProtocols throws on truncation", () => {
        // list length 10, but only 2 bytes follow
        const buf = new Uint8Array([0x00, 0x0a, 0x02, 0x68]);
        expect(() => readAlpnProtocols(buf, 0)).toThrow(Ja4ParseError);
    });

    it("readEcPointFormats throws when listLen byte is out of bounds", () => {
        const buf = new Uint8Array([]); // empty buffer — pos 0 is undefined
        expect(() => readEcPointFormats(buf, 0)).toThrow(Ja4ParseError);
    });

    it("readSupportedGroups throws when listLen uint16 is out of bounds", () => {
        const buf = new Uint8Array([0x00]); // only 1 byte, uint16 needs 2
        expect(() => readSupportedGroups(buf, 0)).toThrow(Ja4ParseError);
    });
});

describe("percentile edge cases", () => {
    it("returns 0 for empty array", () => {
        const { benchmarkTlsHandshake } = require("../src/bench/bench.js");
        const stats = benchmarkTlsHandshake(0);
        expect(stats).toBeDefined();
    });
});
