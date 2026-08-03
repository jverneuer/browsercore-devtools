/**
 * Shared test helpers for the devtools test suite.
 *
 * Kept out of the `*.test.ts` glob so vitest does not try to run it as a test file.
 */

/**
 * A minimal but valid PEM-encoded X.509 certificate (v1, self-signed, CN=Helper).
 * Generated once for import so CLI/inspect tests have a stable cert to read.
 */
export function makeMinimalCert(): string {
    // DER bytes of a tiny valid certificate, base64-wrapped in PEM armor.
    const b64 =
        "MIIC6DCCAdACCQCrGrse2wrmWDANBgkqhkiG9w0BAQsFADA2MRUwEwYDVQQDDAxU" +
        "ZXN0IEV4YW1wbGUxEDAOBgNVBAoMB1Rlc3RPcmcxCzAJBgNVBAYTAlVTMB4XDTI2" +
        "MDgwMjExMzQwNloXDTM2MDczMDExMzQwNlowNjEVMBMGA1UEAwwMVGVzdCBFeGFt" +
        "cGxlMRAwDgYDVQQKDAdUZXN0T3JnMQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcN" +
        "AQEBBQADggEPADCCAQoCggEBANfp/xLC5ZPXIM8n60eGcC0FEsmBJfyxO0m3DFNx" +
        "Wg2EuUJ1Ma4JlWEEKnDAfeBAw1+pnbQpACIajxV3vPB9nEyGGfryExuwpwlhH3nQ" +
        "nFe9+o1EmZNHIKsHH1Zxezc824Vt0cRW5djKnJYHFxnP4RvcVJEf4uEXbrC+wuNN" +
        "463hmavnsdrxPd9olAhinE6iOAX5zAa1W3b0xP0OnKU5DhCGDrQ92Cz42GCCnUjf" +
        "/thAU4NLVl580f9iu16LQv8VAp0wTCBTDRz26ai79RAinvg4Fz2qTTxdt2yLOoei" +
        "fiLZe3YRKFAP2EgLTCNYUtIbrqinZ5B2mZXvJxXXUaDunqkCAwEAATANBgkqhkiG" +
        "9w0BAQsFAAOCAQEAKYGbFbgerKl+xkd/cQY6eC86DYVC56ghyJ9LgfkepV1K9H2L" +
        "yjC5TRMHu2C3LJB6Q3S/8paqh5iaT+wQUKxD9sBO2STsEAhNhH6S/WTf7BbCUhmz" +
        "5HjJ8MMkf0TvRUYe1LHHvIuAwp7RWaKm1R/c8zx07dvGX5Vj/+N5O+m4t14hGrCC" +
        "6rFPX0yvVIRucmfgVwezdZRa/1wwUaW8ft0Zcgk79C1HLdn2oYjlDh3EYmj/B0ul" +
        "QGbtZchxlogEy7W/v22cNypLlaRRkOYoXkC77I5+yCShVfqEPqCTrzMu7zi0EtdM" +
        "ezen4FLFuPGLzooovE/t9eIesAKmu47vWNxpZA==";
    const lines = b64.match(/.{1,64}/g) ?? [];
    return ["-----BEGIN CERTIFICATE-----", ...lines, "-----END CERTIFICATE-----"].join("\n");
}

// ---------------------------------------------------------------------------
// ASN.1 DER building primitives — used by the cert edge-case tests to assemble
// minimal (and deliberately malformed) certificates without openssl.
// ---------------------------------------------------------------------------

const ENC = new TextEncoder();

/** Decode a hex string (whitespace tolerated) into bytes. */
export function fromHex(hex: string): Uint8Array {
    const clean = hex.replace(/\s+/g, "");
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
}

/** Concatenate Uint8Array parts into a single buffer. */
export function concat(parts: readonly Uint8Array[]): Uint8Array {
    const total = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const p of parts) {
        out.set(p, off);
        off += p.length;
    }
    return out;
}

/** Wrap content in a single DER TLV (short or long-form length). */
export function tlv(tag: number, content: Uint8Array): Uint8Array {
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

/** SEQUENCE (constructed). */
export function seq(...parts: Uint8Array[]): Uint8Array {
    return tlv(0x30, concat(parts));
}

/** SET (constructed). */
export function setof(...parts: Uint8Array[]): Uint8Array {
    return tlv(0x31, concat(parts));
}

export function oidTlv(content: Uint8Array): Uint8Array {
    return tlv(0x06, content);
}
export function intTlv(hex: string): Uint8Array {
    return tlv(0x02, fromHex(hex));
}
export function nullTlv(): Uint8Array {
    return tlv(0x05, new Uint8Array());
}
export function boolTlv(value: boolean): Uint8Array {
    return tlv(0x01, new Uint8Array([value ? 0xff : 0x00]));
}
export function octetTlv(content: Uint8Array): Uint8Array {
    return tlv(0x04, content);
}
export function bitStringTlv(content: Uint8Array): Uint8Array {
    return tlv(0x03, content);
}
export function utf8Tlv(s: string): Uint8Array {
    return tlv(0x0c, ENC.encode(s));
}
export function printableStringTlv(s: string): Uint8Array {
    return tlv(0x13, ENC.encode(s));
}
export function ia5StringTlv(s: string): Uint8Array {
    return tlv(0x16, ENC.encode(s));
}
/** Context-specific constructed [tag] wrapper. */
export function contextTlv(tag: number, content: Uint8Array): Uint8Array {
    return tlv(0xa0 | (tag & 0x1f), content);
}

/** A RelativeDistinguishedName: SET { SEQUENCE { OID, value } }. */
export function rdn(oid: Uint8Array, value: Uint8Array): Uint8Array {
    return setof(seq(oidTlv(oid), value));
}

/** A Distinguished Name (RDNSequence). */
export function dn(...rdns: Uint8Array[]): Uint8Array {
    return seq(...rdns);
}

/** Validity SEQUENCE with UTCTime notBefore / notAfter (ASCII strings). */
export function validityUtc(nb: string, na: string): Uint8Array {
    return seq(tlv(0x17, ENC.encode(nb)), tlv(0x17, ENC.encode(na)));
}

/** dNSName GeneralName (context-specific [2], primitive). */
export function dnsName(name: string): Uint8Array {
    return tlv(0x82, ENC.encode(name));
}

/** Build the SubjectAltName SEQUENCE OF GeneralName body. */
export function sanValue(...names: Uint8Array[]): Uint8Array {
    return seq(...names);
}

/** A single Extension: SEQUENCE { OID, [critical BOOLEAN], OCTET STRING }. */
export function extension(oid: Uint8Array, valueOctets: Uint8Array, critical?: boolean): Uint8Array {
    const parts: Uint8Array[] = [oidTlv(oid)];
    if (critical !== undefined) {
        parts.push(boolTlv(critical));
    }
    parts.push(octetTlv(valueOctets));
    return seq(...parts);
}

/** The [3] EXPLICIT extensions wrapper holding a SEQUENCE OF Extension. */
export function extensionsWrapper(...exts: Uint8Array[]): Uint8Array {
    return contextTlv(3, seq(...exts));
}

// Known OID content bytes (sub-identifiers only, no tag/length).
export const OID_CN = fromHex("550403"); // 2.5.4.3  -> CN
export const OID_OU = fromHex("55040b"); // 2.5.4.11 -> OU
export const OID_COUNTRY = fromHex("550406"); // 2.5.4.6 -> C
export const OID_UNKNOWN_DN = fromHex("2a030405"); // 1.2.3.4.5 (not in OID_NAMES)
export const OID_SHA256_RSA = fromHex("2a864886f70d01010b"); // 1.2.840.113549.1.1.11
export const OID_SAN = fromHex("551d11"); // 2.5.29.17 subjectAltName
export const OID_KEY_USAGE = fromHex("551d0f"); // 2.5.29.15 keyUsage (non-SAN)
/** Minimal rsaEncryption AlgorithmIdentifier. */
export const PUBKEY_RSAENC = fromHex("300d06092a864886f70d0101010500");

/** Default UTCTime validity window (2020 -> 2031). */
const DEFAULT_VALIDITY = validityUtc("201010100000Z", "310101000000Z");

export interface BuildCertOptions {
    /** Include the [0] EXPLICIT v3 version wrapper. */
    versionWrapper?: boolean;
    serialHex?: string;
    issuer?: Uint8Array;
    subject?: Uint8Array;
    validity?: Uint8Array;
    sigAlg?: Uint8Array;
    pubKeyInfo?: Uint8Array;
    /** Full [3] extensions wrapper TLV (use extensionsWrapper() to build). */
    extensionsWrapper?: Uint8Array;
}

/** Assemble a (cryptographically bogus but structurally valid) DER certificate. */
export function buildCert(o: BuildCertOptions = {}): Uint8Array {
    const sigAlg = o.sigAlg ?? seq(oidTlv(OID_SHA256_RSA), nullTlv());
    const issuer = o.issuer ?? dn(rdn(OID_CN, utf8Tlv("Root")));
    const subject = o.subject ?? dn(rdn(OID_CN, utf8Tlv("Leaf")));
    const validity = o.validity ?? DEFAULT_VALIDITY;
    const pubKeyInfo = o.pubKeyInfo ?? PUBKEY_RSAENC;
    const serial = intTlv(o.serialHex ?? "42");
    const bodyParts: Uint8Array[] = [];
    if (o.versionWrapper) {
        bodyParts.push(contextTlv(0, intTlv("02")));
    }
    bodyParts.push(serial, sigAlg, issuer, validity, subject, pubKeyInfo);
    if (o.extensionsWrapper) {
        bodyParts.push(o.extensionsWrapper);
    }
    const tbs = seq(...bodyParts);
    const signature = bitStringTlv(fromHex("00"));
    return seq(tbs, sigAlg, signature);
}
