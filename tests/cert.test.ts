import { describe, expect, it } from "vitest";
import { inspectCertificate } from "../src/cert/certInspector.js";
import { CertParseError } from "../src/errors.js";

/** Build a DER buffer from a hex string. */
function fromHex(hex: string): Uint8Array {
    const clean = hex.replace(/\s+/g, "");
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
}

/** Wrap content in a DER TLV with the given tag. */
function tlv(tag: number, content: Uint8Array): Uint8Array {
    const len = content.length;
    let lenBytes: number[];
    if (len < 0x80) {
        lenBytes = [len];
    } else {
        const bytes: number[] = [];
        let remaining = len;
        while (remaining > 0) {
            bytes.unshift(remaining & 0xff);
            remaining >>= 8;
        }
        lenBytes = [0x80 | bytes.length, ...bytes];
    }
    return new Uint8Array([tag, ...lenBytes, ...content]);
}

/** Encode a UTF8String TLV. */
function utf8Tlv(s: string): Uint8Array {
    return tlv(0x0c, new TextEncoder().encode(s));
}

/** Encode an OID TLV from its encoded sub-identifier bytes (without tag/length). */
function oidTlv(encoded: Uint8Array): Uint8Array {
    return tlv(0x06, encoded);
}

const OID_CN = fromHex("550403"); // 2.5.4.3
const OID_SHA256_RSA = fromHex("2a864886f70d01010b"); // 1.2.840.113549.1.1.11

/** A minimal valid v1 DER certificate (no version wrapper, no extensions). */
function makeV1Cert(serial: number, issuerCn: string, subjectCn: string): Uint8Array {
    const serialTlv = tlv(0x02, fromHex(serial.toString(16).padStart(2, "0")));
    const sigAlg = tlv(0x30, new Uint8Array([...oidTlv(OID_SHA256_RSA), ...tlv(0x05, new Uint8Array())]));
    const issuer = tlv(
        0x30,
        tlv(0x31, tlv(0x30, new Uint8Array([...oidTlv(OID_CN), ...utf8Tlv(issuerCn)]))),
    );
    const validity = tlv(
        0x30,
        new Uint8Array([
            ...tlv(0x17, fromHex("323031303130303030305a")), // 201010100000Z
            ...tlv(0x17, fromHex("333130313031303030305a")), // 310101010000Z
        ]),
    );
    const subject = tlv(
        0x30,
        tlv(0x31, tlv(0x30, new Uint8Array([...oidTlv(OID_CN), ...utf8Tlv(subjectCn)]))),
    );
    const pubKeyInfo = fromHex("300d06092a864886f70d0101010500"); // rsaEncryption
    const tbs = tlv(
        0x30,
        new Uint8Array([...serialTlv, ...sigAlg, ...issuer, ...validity, ...subject, ...pubKeyInfo]),
    );
    const signature = tlv(0x03, fromHex("00")); // BIT STRING, empty (not validated)
    return tlv(0x30, new Uint8Array([...tbs, ...sigAlg, ...signature]));
}

const OID_O = fromHex("550a"); // 2.5.4.10  organizationName
const OID_SAN = fromHex("551d11"); // 2.5.29.17  subjectAltName

/** A minimal valid v3 DER certificate with a SAN extension. */
function makeV3CertWithSan(
    serial: number,
    issuerOrg: string,
    subjectCn: string,
    sanDnsNames: string[],
): Uint8Array {
    const serialTlv = tlv(0x02, fromHex(serial.toString(16).padStart(2, "0")));
    const sigAlg = tlv(0x30, new Uint8Array([...oidTlv(OID_SHA256_RSA), ...tlv(0x05, new Uint8Array())]));
    const issuer = tlv(
        0x30,
        tlv(0x31, tlv(0x30, new Uint8Array([...oidTlv(OID_O), ...utf8Tlv(issuerOrg)]))),
    );
    const validity = tlv(
        0x30,
        new Uint8Array([
            ...tlv(0x17, fromHex("323031303130303030305a")),
            ...tlv(0x17, fromHex("333130313031303030305a")),
        ]),
    );
    const subject = tlv(
        0x30,
        tlv(0x31, tlv(0x30, new Uint8Array([...oidTlv(OID_CN), ...utf8Tlv(subjectCn)]))),
    );
    const pubKeyInfo = fromHex("300d06092a864886f70d0101010500");

    // SAN extension: SEQUENCE of [2] IMPLICIT dNSName
    const sanParts: number[] = [];
    for (const dns of sanDnsNames) {
        sanParts.push(...tlv(0x82, new TextEncoder().encode(dns)));
    }
    const sanValue = tlv(0x30, new Uint8Array(sanParts));
    const sanExt = tlv(0x30, new Uint8Array([...oidTlv(OID_SAN), ...tlv(0x04, sanValue)]));

    // Extensions wrapper: [3] EXPLICIT SEQUENCE
    const extensions = tlv(0xa3, tlv(0x30, sanExt));

    // Version v3: [0] EXPLICIT INTEGER 2
    const version = tlv(0xa0, tlv(0x02, new Uint8Array([0x02])));

    const tbs = tlv(
        0x30,
        new Uint8Array([...version, ...serialTlv, ...sigAlg, ...issuer, ...validity, ...subject, ...pubKeyInfo, ...extensions]),
    );
    const signature = tlv(0x03, fromHex("00"));
    return tlv(0x30, new Uint8Array([...tbs, ...sigAlg, ...signature]));
}

const v1Der = makeV1Cert(0x42, "Root", "Leaf");
const v3SanDer = makeV3CertWithSan(0x99, "TestOrg", "san.example.com", ["san.example.com", "alt.example.com"]);

const PEM_HEADER = "-----BEGIN CERTIFICATE-----\n";
const PEM_FOOTER = "\n-----END CERTIFICATE-----";

/** Wrap base64 text in PEM armor. */
function toPem(b64: string): string {
    const lines = b64.match(/.{1,64}/g) ?? [];
    return PEM_HEADER + lines.join("\n") + PEM_FOOTER;
}

describe("inspectCertificate", () => {
    describe("happy paths", () => {
        it("parses a DER v1 certificate", () => {
            const info = inspectCertificate(v1Der);
            expect(info.subject).toContain("CN=Leaf");
            expect(info.issuer).toContain("CN=Root");
            expect(info.san).toEqual([]);
            expect(info.notBefore).toBeInstanceOf(Date);
            expect(info.notAfter).toBeInstanceOf(Date);
            expect(info.fingerprintSha256).toMatch(/^[0-9a-f]{2}(:[0-9a-f]{2}){31}$/);
        });

        it("parses a PEM certificate (strips armor)", () => {
            const b64 = v1Der.reduce((acc, b) => acc + String.fromCharCode(b), "");
            const pem = toPem(btoa(b64));
            const info = inspectCertificate(new TextEncoder().encode(pem));
            expect(info.subject).toContain("CN=Leaf");
        });

        it("parses a v3 certificate with a SAN extension and extracts DNS names", () => {
            const info = inspectCertificate(v3SanDer);
            expect(info.subject).toContain("CN=san.example.com");
            expect(info.issuer).toContain("TestOrg");
            expect(info.san).toEqual(["san.example.com", "alt.example.com"]);
        });

        it("computes a stable SHA-256 fingerprint over the whole DER blob", () => {
            const a = inspectCertificate(v1Der);
            const b = inspectCertificate(v1Der);
            expect(a.fingerprintSha256).toBe(b.fingerprintSha256);
        });
    });

    describe("DER structural errors", () => {
        it("throws CertParseError on empty input", () => {
            expect(() => inspectCertificate(new Uint8Array())).toThrow(CertParseError);
            expect(() => inspectCertificate(new Uint8Array())).toThrow("empty certificate input");
        });

        it("throws CertParseError when the top-level tag is not a SEQUENCE", () => {
            const der = fromHex("3100"); // SET, empty
            expect(() => inspectCertificate(der)).toThrow(/expected SEQUENCE, got 0x/);
        });

        it("throws CertParseError on a truncated TBS body", () => {
            // SEQUENCE { SEQUENCE { INTEGER 0x42 } } — TBS has no validity/subject.
            const tbs = tlv(0x30, tlv(0x02, fromHex("42")));
            const cert = tlv(0x30, tbs);
            expect(() => inspectCertificate(cert)).toThrow(CertParseError);
        });

        it("throws CertParseError on a TLV whose length exceeds the buffer", () => {
            // SEQUENCE claiming a 3-byte long-form length (0x82) but the length bytes
            // describe more content than the buffer holds.
            const der = fromHex("3082000500"); // length says 5, but only 1 byte follows
            expect(() => inspectCertificate(der)).toThrow(/TLV length .* exceeds buffer/);
        });

        it("throws CertParseError on an unsupported DER length form", () => {
            // SEQUENCE with a 5-byte long-form length (nbytes > 4 is rejected).
            const der = fromHex("30850000000000");
            expect(() => inspectCertificate(der)).toThrow(/unsupported DER length form: 0x85/);
        });

        it("throws CertParseError on a truncated DER length", () => {
            // SEQUENCE with long-form header saying 2 bytes of length, but only 1 follows.
            const der = fromHex("308201");
            expect(() => inspectCertificate(der)).toThrow(/truncated DER long-form length/);
        });

        it("throws CertParseError on an unsupported tag class", () => {
            // Application-specific constructed class (0x40 | 0x20 = 0x60) is neither universal nor context.
            // Build an outer SEQUENCE whose first inner TLV carries the bad tag.
            const bad = tlv(0x60, fromHex("0500")); // app-specific constructed
            const cert = tlv(0x30, new Uint8Array([...bad, ...fromHex("0500")]));
            expect(() => inspectCertificate(cert)).toThrow(/unsupported tag class: 0x40/);
        });

        it("throws CertParseError when a DN attribute is not a SET", () => {
            // Issuer RDN is a SEQUENCE instead of a SET.
            const issuerRdn = tlv(0x30, new Uint8Array([...oidTlv(OID_CN), ...utf8Tlv("Root")]));
            const issuer = tlv(0x30, issuerRdn);
            const validity = tlv(
                0x30,
                new Uint8Array([...tlv(0x17, fromHex("323031303130303030305a")), ...tlv(0x17, fromHex("333130313031303030305a"))]),
            );
            const subject = tlv(0x30, tlv(0x31, tlv(0x30, new Uint8Array([...oidTlv(OID_CN), ...utf8Tlv("Leaf")]))));
            const sigAlg = tlv(0x30, new Uint8Array([...oidTlv(OID_SHA256_RSA), ...tlv(0x05, new Uint8Array())]));
            const pubKeyInfo = fromHex("300d06092a864886f70d0101010500");
            const tbs = tlv(
                0x30,
                new Uint8Array([...tlv(0x02, fromHex("42")), ...sigAlg, ...issuer, ...validity, ...subject, ...pubKeyInfo]),
            );
            const signature = tlv(0x03, fromHex("00"));
            const cert = tlv(0x30, new Uint8Array([...tbs, ...sigAlg, ...signature]));
            expect(() => inspectCertificate(cert)).toThrow(/expected SET in RDN, got 0x30/);
        });

        it("throws CertParseError when an attribute value tag is not a string type", () => {
            // CN attribute with INTEGER value (0x02) instead of a string tag.
            const badAttr = tlv(0x30, new Uint8Array([...oidTlv(OID_CN), ...tlv(0x02, fromHex("42"))]));
            const subject = tlv(0x30, tlv(0x31, badAttr));
            const validity = tlv(
                0x30,
                new Uint8Array([...tlv(0x17, fromHex("323031303130303030305a")), ...tlv(0x17, fromHex("333130313031303030305a"))]),
            );
            const issuer = tlv(0x30, tlv(0x31, tlv(0x30, new Uint8Array([...oidTlv(OID_CN), ...utf8Tlv("Root")]))));
            const sigAlg = tlv(0x30, new Uint8Array([...oidTlv(OID_SHA256_RSA), ...tlv(0x05, new Uint8Array())]));
            const pubKeyInfo = fromHex("300d06092a864886f70d0101010500");
            const tbs = tlv(
                0x30,
                new Uint8Array([...tlv(0x02, fromHex("42")), ...sigAlg, ...issuer, ...validity, ...subject, ...pubKeyInfo]),
            );
            const signature = tlv(0x03, fromHex("00"));
            const cert = tlv(0x30, new Uint8Array([...tbs, ...sigAlg, ...signature]));
            expect(() => inspectCertificate(cert)).toThrow(/unsupported string tag 0x2 in DN/);
        });

        it("throws CertParseError when the validity time tag is not UTCTime/GeneralizedTime", () => {
            // Validity SEQUENCE with two elements, the second an INTEGER instead of a time.
            const badValidity = tlv(
                0x30,
                new Uint8Array([...tlv(0x17, fromHex("323031303130303030305a")), ...tlv(0x02, fromHex("42"))]),
            );
            const subject = tlv(0x30, tlv(0x31, tlv(0x30, new Uint8Array([...oidTlv(OID_CN), ...utf8Tlv("Leaf")]))));
            const issuer = tlv(0x30, tlv(0x31, tlv(0x30, new Uint8Array([...oidTlv(OID_CN), ...utf8Tlv("Root")]))));
            const sigAlg = tlv(0x30, new Uint8Array([...oidTlv(OID_SHA256_RSA), ...tlv(0x05, new Uint8Array())]));
            const pubKeyInfo = fromHex("300d06092a864886f70d0101010500");
            const tbs = tlv(
                0x30,
                new Uint8Array([...tlv(0x02, fromHex("42")), ...sigAlg, ...issuer, ...badValidity, ...subject, ...pubKeyInfo]),
            );
            const signature = tlv(0x03, fromHex("00"));
            const cert = tlv(0x30, new Uint8Array([...tbs, ...sigAlg, ...signature]));
            expect(() => inspectCertificate(cert)).toThrow(/expected time tag, got 0x2/);
        });
    });

    describe("OID parsing errors", () => {
        it("throws CertParseError on an empty OID", () => {
            const badAttr = tlv(0x30, new Uint8Array([...tlv(0x06, new Uint8Array()), ...utf8Tlv("Leaf")]));
            const subject = tlv(0x30, tlv(0x31, badAttr));
            const validity = tlv(
                0x30,
                new Uint8Array([...tlv(0x17, fromHex("323031303130303030305a")), ...tlv(0x17, fromHex("333130313031303030305a"))]),
            );
            const issuer = tlv(0x30, tlv(0x31, tlv(0x30, new Uint8Array([...oidTlv(OID_CN), ...utf8Tlv("Root")]))));
            const sigAlg = tlv(0x30, new Uint8Array([...oidTlv(OID_SHA256_RSA), ...tlv(0x05, new Uint8Array())]));
            const pubKeyInfo = fromHex("300d06092a864886f70d0101010500");
            const tbs = tlv(
                0x30,
                new Uint8Array([...tlv(0x02, fromHex("42")), ...sigAlg, ...issuer, ...validity, ...subject, ...pubKeyInfo]),
            );
            const signature = tlv(0x03, fromHex("00"));
            const cert = tlv(0x30, new Uint8Array([...tbs, ...sigAlg, ...signature]));
            expect(() => inspectCertificate(cert)).toThrow(/empty OID/);
        });

        it("throws CertParseError on a truncated OID", () => {
            // OID content 02 8f: first byte completes a node, second has the
            // continuation high bit set but no follow-up byte → truncated.
            const badAttr = tlv(0x30, new Uint8Array([...tlv(0x06, fromHex("028f")), ...utf8Tlv("Leaf")]));
            const subject = tlv(0x30, tlv(0x31, badAttr));
            const validity = tlv(
                0x30,
                new Uint8Array([...tlv(0x17, fromHex("323031303130303030305a")), ...tlv(0x17, fromHex("333130313031303030305a"))]),
            );
            const issuer = tlv(0x30, tlv(0x31, tlv(0x30, new Uint8Array([...oidTlv(OID_CN), ...utf8Tlv("Root")]))));
            const sigAlg = tlv(0x30, new Uint8Array([...oidTlv(OID_SHA256_RSA), ...tlv(0x05, new Uint8Array())]));
            const pubKeyInfo = fromHex("300d06092a864886f70d0101010500");
            const tbs = tlv(
                0x30,
                new Uint8Array([...tlv(0x02, fromHex("42")), ...sigAlg, ...issuer, ...validity, ...subject, ...pubKeyInfo]),
            );
            const signature = tlv(0x03, fromHex("00"));
            const cert = tlv(0x30, new Uint8Array([...tbs, ...sigAlg, ...signature]));
            expect(() => inspectCertificate(cert)).toThrow(/truncated OID/);
        });
    });

    describe("rewind / offset cursor mechanics", () => {
        it("parses an extension with an optional critical BOOLEAN by rewinding when absent", () => {
            // SAN extension WITHOUT a critical field: the next TLV after the OID is the
            // OCTET STRING (tag 0x04 != 0x01 BOOLEAN), so the cursor must rewind and
            // then read the OCTET STRING.
            const sanValue = tlv(
                0x30,
                new Uint8Array([...tlv(0x82, new TextEncoder().encode("san.example.com")), ...tlv(0x82, new TextEncoder().encode("alt.example.com"))]),
            );
            const extValue = new Uint8Array([...tlv(0x06, fromHex("551d11")), ...tlv(0x04, sanValue)]); // OID 2.5.29.17, OCTET STRING
            const ext = tlv(0x30, extValue);
            const extensions = tlv(0xa3, tlv(0x30, ext)); // [3] { SEQUENCE OF Extension }
            const sigAlg = tlv(0x30, new Uint8Array([...oidTlv(OID_SHA256_RSA), ...tlv(0x05, new Uint8Array())]));
            const issuer = tlv(0x30, tlv(0x31, tlv(0x30, new Uint8Array([...oidTlv(OID_CN), ...utf8Tlv("Root")]))));
            const validity = tlv(
                0x30,
                new Uint8Array([...tlv(0x17, fromHex("323031303130303030305a")), ...tlv(0x17, fromHex("333130313031303030305a"))]),
            );
            const subject = tlv(0x30, tlv(0x31, tlv(0x30, new Uint8Array([...oidTlv(OID_CN), ...utf8Tlv("Leaf")]))));
            const pubKeyInfo = fromHex("300d06092a864886f70d0101010500");
            const tbsBody = new Uint8Array([...tlv(0x02, fromHex("42")), ...sigAlg, ...issuer, ...validity, ...subject, ...pubKeyInfo, ...extensions]);
            const version = tlv(0xa0, tlv(0x02, fromHex("02"))); // [0] { INTEGER 2 }
            const tbs = tlv(0x30, new Uint8Array([...version, ...tbsBody]));
            const signature = tlv(0x03, fromHex("00"));
            const cert = tlv(0x30, new Uint8Array([...tbs, ...sigAlg, ...signature]));
            const info = inspectCertificate(cert);
            expect(info.san).toEqual(["san.example.com", "alt.example.com"]);
        });

        it("parses an extension with a critical BOOLEAN present (no rewind needed)", () => {
            const sanValue = tlv(0x30, tlv(0x82, new TextEncoder().encode("san.example.com")));
            const extValue = new Uint8Array([
                ...tlv(0x06, fromHex("551d11")), // OID 2.5.29.17
                ...tlv(0x01, fromHex("ff")), // BOOLEAN TRUE (critical)
                ...tlv(0x04, sanValue), // OCTET STRING
            ]);
            const ext = tlv(0x30, extValue);
            const extensions = tlv(0xa3, tlv(0x30, ext));
            const sigAlg = tlv(0x30, new Uint8Array([...oidTlv(OID_SHA256_RSA), ...tlv(0x05, new Uint8Array())]));
            const issuer = tlv(0x30, tlv(0x31, tlv(0x30, new Uint8Array([...oidTlv(OID_CN), ...utf8Tlv("Root")]))));
            const validity = tlv(
                0x30,
                new Uint8Array([...tlv(0x17, fromHex("323031303130303030305a")), ...tlv(0x17, fromHex("333130313031303030305a"))]),
            );
            const subject = tlv(0x30, tlv(0x31, tlv(0x30, new Uint8Array([...oidTlv(OID_CN), ...utf8Tlv("Leaf")]))));
            const pubKeyInfo = fromHex("300d06092a864886f70d0101010500");
            const tbsBody = new Uint8Array([...tlv(0x02, fromHex("42")), ...sigAlg, ...issuer, ...validity, ...subject, ...pubKeyInfo, ...extensions]);
            const version = tlv(0xa0, tlv(0x02, fromHex("02")));
            const tbs = tlv(0x30, new Uint8Array([...version, ...tbsBody]));
            const signature = tlv(0x03, fromHex("00"));
            const cert = tlv(0x30, new Uint8Array([...tbs, ...sigAlg, ...signature]));
            const info = inspectCertificate(cert);
            expect(info.san).toEqual(["san.example.com"]);
        });

        it("returns [] when the SAN OCTET STRING is not a SEQUENCE wrapper", () => {
            // OCTET STRING content that is not a SEQUENCE (NULL) → parseSan returns [].
            const extValue = new Uint8Array([
                ...tlv(0x06, fromHex("551d11")), // OID 2.5.29.17
                ...tlv(0x04, tlv(0x05, new Uint8Array())), // OCTET STRING containing NULL
            ]);
            const ext = tlv(0x30, extValue);
            const extensions = tlv(0xa3, tlv(0x30, ext));
            const sigAlg = tlv(0x30, new Uint8Array([...oidTlv(OID_SHA256_RSA), ...tlv(0x05, new Uint8Array())]));
            const issuer = tlv(0x30, tlv(0x31, tlv(0x30, new Uint8Array([...oidTlv(OID_CN), ...utf8Tlv("Root")]))));
            const validity = tlv(
                0x30,
                new Uint8Array([...tlv(0x17, fromHex("323031303130303030305a")), ...tlv(0x17, fromHex("333130313031303030305a"))]),
            );
            const subject = tlv(0x30, tlv(0x31, tlv(0x30, new Uint8Array([...oidTlv(OID_CN), ...utf8Tlv("Leaf")]))));
            const pubKeyInfo = fromHex("300d06092a864886f70d0101010500");
            const tbsBody = new Uint8Array([...tlv(0x02, fromHex("42")), ...sigAlg, ...issuer, ...validity, ...subject, ...pubKeyInfo, ...extensions]);
            const version = tlv(0xa0, tlv(0x02, fromHex("02")));
            const tbs = tlv(0x30, new Uint8Array([...version, ...tbsBody]));
            const signature = tlv(0x03, fromHex("00"));
            const cert = tlv(0x30, new Uint8Array([...tbs, ...sigAlg, ...signature]));
            const info = inspectCertificate(cert);
            expect(info.san).toEqual([]);
        });

        it("returns [] when there are no extensions at all", () => {
            const info = inspectCertificate(v1Der);
            expect(info.san).toEqual([]);
        });
    });

    describe("error wrapping", () => {
        it("preserves CertParseError kind on rethrow", () => {
            try {
                inspectCertificate(new Uint8Array());
            } catch (err) {
                expect(err).toBeInstanceOf(CertParseError);
                expect((err as CertParseError).kind).toBe("CertParseError");
                return;
            }
            throw new Error("expected to throw");
        });
    });
});
