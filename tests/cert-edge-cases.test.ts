import { describe, expect, it } from "vitest";
import { inspectCertificate } from "../src/cert/certInspector.js";
import { CertParseError } from "../src/errors.js";
import {
    buildCert,
    dn,
    extension,
    extensionsWrapper,
    dnsName,
    makeMinimalCert,
    octetTlv,
    oidTlv,
    rdn,
    sanValue,
    seq,
    intTlv,
    nullTlv,
    setof,
    utf8Tlv,
    contextTlv,
    fromHex,
    tlv,
    OID_CN,
    OID_SAN,
    OID_KEY_USAGE,
    OID_UNKNOWN_DN,
    OID_SHA256_RSA,
} from "./_testhelpers.js";

describe("inspectCertificate — TBS structural errors", () => {
    it("throws 'malformed TBSCertificate' when the TBS element is not a SEQUENCE", () => {
        // Outer SEQUENCE whose first child (the TBS) is NULL.
        const cert = seq(nullTlv(), seq(oidTlv(OID_SHA256_RSA), nullTlv()), new Uint8Array());
        expect(() => inspectCertificate(cert)).toThrow(CertParseError);
        expect(() => inspectCertificate(cert)).toThrow(/malformed TBSCertificate/);
    });
});

describe("inspectCertificate — distinguished-name parsing", () => {
    it("falls back to the raw OID when it is not in the short-name table", () => {
        // 1.2.3.4.5 is not in OID_NAMES, so it is rendered verbatim.
        const cert = buildCert({ subject: dn(rdn(OID_UNKNOWN_DN, utf8Tlv("custom-value"))) });
        expect(inspectCertificate(cert).subject).toContain("1.2.3.4.5=custom-value");
    });

    it("renders multiple RDN attributes (OU, CN) joined in order", () => {
        const subject = dn(rdn(fromHex("55040b" /* OU */), utf8Tlv("Engineering")), rdn(OID_CN, utf8Tlv("Leaf")));
        const out = inspectCertificate(buildCert({ subject })).subject;
        expect(out).toContain("OU=Engineering");
        expect(out).toContain("CN=Leaf");
    });

    it("throws when an RDN attribute is not a SEQUENCE", () => {
        // SET whose direct child is an OID TLV (should be SEQUENCE { OID, value }).
        expect(() => inspectCertificate(buildCert({ issuer: dn(setof(oidTlv(OID_CN))) }))).toThrow(
            /expected SEQUENCE in attribute/,
        );
    });

    it("throws when the attribute's first element is not an OID", () => {
        // SEQUENCE { INTEGER, UTF8String } — OID missing.
        expect(() => inspectCertificate(buildCert({ issuer: dn(setof(seq(intTlv("42"), utf8Tlv("Root")))) }))).toThrow(
            /expected OID in attribute/,
        );
    });
});

describe("inspectCertificate — extension / SAN edge cases", () => {
    // NOTE: extension(oid, valueBytes) wraps `valueBytes` in an OCTET STRING itself,
    // so callers pass the *raw* extension value (e.g. the SAN SEQUENCE), not a
    // pre-wrapped OCTET STRING.

    it("extracts SAN from a v3 cert that omits the critical BOOLEAN (rewind path)", () => {
        const cert = buildCert({
            versionWrapper: true,
            extensionsWrapper: extensionsWrapper(
                extension(OID_SAN, sanValue(dnsName("a.example.com"), dnsName("b.example.com"))),
            ),
        });
        expect(inspectCertificate(cert).san).toEqual(["a.example.com", "b.example.com"]);
    });

    it("extracts SAN from a v3 cert that includes a critical BOOLEAN", () => {
        const cert = buildCert({
            versionWrapper: true,
            extensionsWrapper: extensionsWrapper(
                extension(OID_SAN, sanValue(dnsName("crit.example.com")), true),
            ),
        });
        expect(inspectCertificate(cert).san).toEqual(["crit.example.com"]);
    });

    it("walks a [3] extensions wrapper in the version-less (rewound) TBS path", () => {
        // No [0] version wrapper, but a [3] extensions block is present — exercises
        // parseTbsRewound's extension scan (a previously uncovered branch).
        const cert = buildCert({
            versionWrapper: false,
            extensionsWrapper: extensionsWrapper(extension(OID_SAN, sanValue(dnsName("rewound.example.com")))),
        });
        expect(inspectCertificate(cert).san).toEqual(["rewound.example.com"]);
    });

    it("skips a non-SAN extension and still finds the SAN extension", () => {
        // Key Usage (2.5.29.15) is not the SAN OID and must be skipped.
        const cert = buildCert({
            versionWrapper: true,
            extensionsWrapper: extensionsWrapper(
                extension(OID_KEY_USAGE, new Uint8Array([0x03])),
                extension(OID_SAN, sanValue(dnsName("after-keyusage.example.com"))),
            ),
        });
        expect(inspectCertificate(cert).san).toEqual(["after-keyusage.example.com"]);
    });

    it("skips an extension whose wrapper is not a SEQUENCE", () => {
        // First "extension" is a bare NULL; the real SAN follows.
        const cert = buildCert({
            versionWrapper: true,
            extensionsWrapper: extensionsWrapper(
                nullTlv(),
                extension(OID_SAN, sanValue(dnsName("skip-null.example.com"))),
            ),
        });
        expect(inspectCertificate(cert).san).toEqual(["skip-null.example.com"]);
    });

    it("skips an extension whose first element is not an OID", () => {
        // SEQUENCE { INTEGER, OCTET STRING } — not a recognizable extension.
        const cert = buildCert({
            versionWrapper: true,
            extensionsWrapper: extensionsWrapper(
                seq(intTlv("42"), octetTlv(sanValue(dnsName("ignored.example.com")))),
                extension(OID_SAN, sanValue(dnsName("kept.example.com"))),
            ),
        });
        expect(inspectCertificate(cert).san).toEqual(["kept.example.com"]);
    });

    it("skips a SAN extension that has no OCTET STRING wrapper (only the OID)", () => {
        const cert = buildCert({
            versionWrapper: true,
            extensionsWrapper: extensionsWrapper(
                seq(oidTlv(OID_SAN)),
                extension(OID_SAN, sanValue(dnsName("after-bare.example.com"))),
            ),
        });
        expect(inspectCertificate(cert).san).toEqual(["after-bare.example.com"]);
    });

    it("skips a SAN extension whose value is not an OCTET STRING", () => {
        // After the OID, the next TLV is NULL (rewound), not OCTET STRING.
        const cert = buildCert({
            versionWrapper: true,
            extensionsWrapper: extensionsWrapper(
                seq(oidTlv(OID_SAN), nullTlv()),
                extension(OID_SAN, sanValue(dnsName("after-bad-octet.example.com"))),
            ),
        });
        expect(inspectCertificate(cert).san).toEqual(["after-bad-octet.example.com"]);
    });

    it("returns [] when the [3] extensions block is empty", () => {
        const cert = buildCert({ versionWrapper: true, extensionsWrapper: contextTlv(3, new Uint8Array()) });
        expect(inspectCertificate(cert).san).toEqual([]);
    });

    it("returns [] when the extensions wrapper's outer element is not a SEQUENCE", () => {
        // [3] { NULL } — the SEQUENCE OF Extension wrapper is missing.
        const cert = buildCert({ versionWrapper: true, extensionsWrapper: contextTlv(3, nullTlv()) });
        expect(inspectCertificate(cert).san).toEqual([]);
    });

    it("returns [] when the SAN OCTET STRING content is empty", () => {
        const cert = buildCert({
            versionWrapper: true,
            extensionsWrapper: extensionsWrapper(extension(OID_SAN, new Uint8Array())),
        });
        expect(inspectCertificate(cert).san).toEqual([]);
    });

    it("returns [] when the SAN content is not a SEQUENCE wrapper", () => {
        // OCTET STRING wrapping a NULL instead of a SEQUENCE OF GeneralName.
        const cert = buildCert({
            versionWrapper: true,
            extensionsWrapper: extensionsWrapper(extension(OID_SAN, nullTlv())),
        });
        expect(inspectCertificate(cert).san).toEqual([]);
    });

    it("ignores non-dNSName GeneralName entries inside the SAN", () => {
        // rfc822Name is context-specific [1] (primitive tag 0x81); only [2] (0x82)
        // dNSName entries are collected.
        const rfc822 = tlv(0x81, new TextEncoder().encode("ignored@example.com"));
        const cert = buildCert({
            versionWrapper: true,
            extensionsWrapper: extensionsWrapper(
                extension(OID_SAN, sanValue(rfc822, dnsName("only-dns.example.com"))),
            ),
        });
        expect(inspectCertificate(cert).san).toEqual(["only-dns.example.com"]);
    });
});

describe("inspectCertificate — error wrapping contract", () => {
    it("rethrows an inner CertParseError without rewrapping the message", () => {
        // A non-SEQUENCE top-level tag throws CertParseError inside the try block,
        // which must be rethrown as-is (not wrapped in "failed to parse certificate").
        try {
            inspectCertificate(new Uint8Array([0x31, 0x00]));
        } catch (err) {
            expect(err).toBeInstanceOf(CertParseError);
            expect((err as CertParseError).message).not.toContain("failed to parse certificate");
            return;
        }
        throw new Error("expected to throw");
    });

    it("wraps an invalid-base64 PEM body in CertParseError (not a raw DOMException)", () => {
        // maybePemToDer() now runs INSIDE the try/catch in inspectCertificate, so the
        // atob() failure is converted into CertParseError, honoring the documented
        // "throws CertParseError on anything it cannot interpret" contract.
        const badPem = "-----BEGIN CERTIFICATE-----\n!!!!not-base64!!!!\n-----END CERTIFICATE-----";
        expect(() => inspectCertificate(new TextEncoder().encode(badPem))).toThrow(CertParseError);
        try {
            inspectCertificate(new TextEncoder().encode(badPem));
        } catch (err) {
            expect(err).toBeInstanceOf(CertParseError);
            return;
        }
        throw new Error("expected to throw");
    });

    it("skips leading junk lines before the PEM BEGIN marker", () => {
        // maybePemToDer() iterates lines; anything before "-----BEGIN " takes the
        // if (inBody) else path (ignored). A PEM with leading comments must still
        // parse — only the base64 body between the markers is decoded.
        const pem = makeMinimalCert();
        const withJunk = ["# a leading comment", "not-base64-junk", ""].join("\n") + "\n" + pem;
        const info = inspectCertificate(new TextEncoder().encode(withJunk));
        expect(info.subject).toContain("CN=");
        expect(info.issuer).toContain("Test");
        expect(info.fingerprintSha256).toMatch(/^[0-9a-f]{2}(:[0-9a-f]{2}){31}$/);
    });
});
