import { describe, expect, it } from "vitest";
import { registerProfile, type BrowserProfile, type ProfileId } from "@browsercore/profiles";
import {
    createInspectorSession,
    decodeHttp2Frame,
    decodeTlsRecord,
    exportToJson,
    exportToHtml,
    inspectCertificate,
    visualizeHttp2Stream,
    visualizeTlsHandshake,
} from "../src/index.js";
import { diffProfiles } from "../src/diff/profileDiff.js";

describe("createInspectorSession", () => {
    it("returns a session with an empty frames array", () => {
        const session = createInspectorSession();
        expect(session.frames).toEqual([]);
        expect(typeof session.id).toBe("string");
    });

    it("addFrame appends a frame with an auto timestamp", () => {
        const session = createInspectorSession();
        session.addFrame({
            direction: "sent",
            protocol: "tls",
            bytes: new Uint8Array([0x16, 0x03, 0x01]),
            decoded: null,
        });
        expect(session.frames.length).toBe(1);
        const frame = session.frames[0]!;
        expect(frame.direction).toBe("sent");
        expect(frame.protocol).toBe("tls");
        expect(frame.bytes).toEqual(new Uint8Array([0x16, 0x03, 0x01]));
        expect(typeof frame.timestamp).toBe("number");
    });

    it("filter returns matching frames", () => {
        const session = createInspectorSession();
        session.addFrame({ direction: "sent", protocol: "tls", bytes: new Uint8Array(), decoded: null });
        session.addFrame({ direction: "received", protocol: "http2", bytes: new Uint8Array(), decoded: null });
        const tls = session.filter((f) => f.protocol === "tls");
        expect(tls.length).toBe(1);
        expect(tls[0]!.protocol).toBe("tls");
    });
});

describe("decodeTlsRecord", () => {
    it("decodes a handshake record header", () => {
        // ContentType=22 (handshake), version 0x0303, length=4, then a 4-byte fragment.
        const fragment = new Uint8Array([0x01, 0x00, 0x00, 0x20]);
        const record = new Uint8Array([0x16, 0x03, 0x03, 0x00, fragment.length, ...fragment]);
        const decoded = decodeTlsRecord(record);
        expect(decoded.contentType).toBe(22);
        expect(decoded.version).toContain("handshake");
        expect(decoded.fragments.length).toBe(1);
        expect(decoded.fragments[0]!.length).toBe(fragment.length);
    });
});

describe("decodeHttp2Frame", () => {
    it("decodes a SETTINGS frame header", () => {
        // 9-byte frame header: length=0, type=4 (SETTINGS), flags=0, streamId=0.
        const frame = new Uint8Array([0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]);
        const decoded = decodeHttp2Frame(frame);
        expect(decoded.type).toBe(0x04);
        expect(decoded.flags).toBe(0);
        expect(decoded.streamId).toBe(0);
        expect(decoded.payload.length).toBe(0);
    });
});

describe("visualizeTlsHandshake", () => {
    it("returns a non-empty trace for a session with a TLS frame", () => {
        const session = createInspectorSession();
        session.addFrame({
            direction: "sent",
            protocol: "tls",
            bytes: new Uint8Array([0x16, 0x03, 0x03, 0x00, 0x00]),
            decoded: null,
        });
        const out = visualizeTlsHandshake(session);
        expect(typeof out).toBe("string");
        expect(out.length).toBeGreaterThan(0);
        expect(out).toContain("TLS");
    });
});

describe("visualizeHttp2Stream", () => {
    it("returns a non-empty trace for a session with an HTTP/2 frame", () => {
        const session = createInspectorSession();
        session.addFrame({
            direction: "received",
            protocol: "http2",
            bytes: new Uint8Array(9),
            decoded: null,
        });
        const out = visualizeHttp2Stream(session);
        expect(typeof out).toBe("string");
        expect(out.length).toBeGreaterThan(0);
        expect(out).toContain("HTTP/2");
    });
});

describe("diffProfiles", () => {
    it("reports a changed field between two profiles", () => {
        const base = {
            tls: {
                cipherSuites: ["TLS_AES_128_GCM_SHA256"],
                extensionOrder: [],
                supportedVersions: ["TLS 1.3"],
                keyShareGroups: ["x25519"],
                signatureAlgorithms: ["ecdsa_secp256r1_sha256"],
                grease: true,
            },
            http2: {
                settings: { initialWindowSize: 6291456 },
                initialWindowSize: 6291456,
                maxFrameSize: 16384,
                headerTableSize: 65536,
                weight: 255,
            },
            http1: {
                defaultHeaders: { "user-agent": "test/1.0" },
                headerOrder: ["user-agent"],
                connection: "keep-alive" as const,
                acceptEncoding: "gzip",
            },
        };
        const profileA: BrowserProfile = {
            id: "test-a" as ProfileId,
            name: "test",
            version: "1.0",
            ...base,
        };
        const profileB: BrowserProfile = {
            id: "test-b" as ProfileId,
            name: "test",
            version: "1.0",
            ...base,
            tls: {
                ...base.tls,
                cipherSuites: [...base.tls.cipherSuites, "TLS_AES_256_GCM_SHA384"],
            },
        };
        registerProfile(profileA);
        registerProfile(profileB);
        const diff = diffProfiles("test-a" as ProfileId, "test-b" as ProfileId);
        expect(diff.differences.length).toBeGreaterThan(0);
        expect(diff.differences.some((d) => d.path.startsWith("tls/cipherSuites"))).toBe(true);
    });
});

describe("inspectCertificate", () => {
    it("parses a PEM certificate into a summary", () => {
        const pem = `-----BEGIN CERTIFICATE-----
MIIC6DCCAdACCQCrGrse2wrmWDANBgkqhkiG9w0BAQsFADA2MRUwEwYDVQQDDAxU
ZXN0IEV4YW1wbGUxEDAOBgNVBAoMB1Rlc3RPcmcxCzAJBgNVBAYTAlVTMB4XDTI2
MDgwMjExMzQwNloXDTM2MDczMDExMzQwNlowNjEVMBMGA1UEAwwMVGVzdCBFeGFt
cGxlMRAwDgYDVQQKDAdUZXN0T3JnMQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBANfp/xLC5ZPXIM8n60eGcC0FEsmBJfyxO0m3DFNx
Wg2EuUJ1Ma4JlWEEKnDAfeBAw1+pnbQpACIajxV3vPB9nEyGGfryExuwpwlhH3nQ
nFe9+o1EmZNHIKsHH1Zxezc824Vt0cRW5djKnJYHFxnP4RvcVJEf4uEXbrC+wuNN
463hmavnsdrxPd9olAhinE6iOAX5zAa1W3b0xP0OnKU5DhCGDrQ92Cz42GCCnUjf
/thAU4NLVl580f9iu16LQv8VAp0wTCBTDRz26ai79RAinvg4Fz2qTTxdt2yLOoei
fiLZe3YRKFAP2EgLTCNYUtIbrqinZ5B2mZXvJxXXUaDunqkCAwEAATANBgkqhkiG
9w0BAQsFAAOCAQEAKYGbFbgerKl+xkd/cQY6eC86DYVC56ghyJ9LgfkepV1K9H2L
yjC5TRMHu2C3LJB6Q3S/8paqh5iaT+wQUKxD9sBO2STsEAhNhH6S/WTf7BbCUhmz
5HjJ8MMkf0TvRUYe1LHHvIuAwp7RWaKm1R/c8zx07dvGX5Vj/+N5O+m4t14hGrCC
6rFPX0yvVIRucmfgVwezdZRa/1wwUaW8ft0Zcgk79C1HLdn2oYjlDh3EYmj/B0ul
QGbtZchxlogEy7W/v22cNypLlaRRkOYoXkC77I5+yCShVfqEPqCTrzMu7zi0EtdM
ezen4FLFuPGLzooovE/t9eIesAKmu47vWNxpZA==
-----END CERTIFICATE-----`;
        const info = inspectCertificate(new TextEncoder().encode(pem));
        expect(info.subject).toContain("CN=");
        expect(info.issuer).toContain("Test");
        expect(info.fingerprintSha256.length).toBeGreaterThan(0);
        expect(info.notBefore).toBeInstanceOf(Date);
        expect(info.notAfter).toBeInstanceOf(Date);
    });
});

describe("exporters", () => {
    it("exportToJson produces valid indented JSON", () => {
        const json = exportToJson({ a: 1, b: [1, 2] });
        expect(JSON.parse(json)).toEqual({ a: 1, b: [1, 2] });
        expect(json).toContain("\n  ");
    });

    it("exportToHtml wraps data in a self-contained document", () => {
        const html = exportToHtml("My Report", { status: "ok", count: 3 });
        expect(html).toContain("<!DOCTYPE html>");
        expect(html).toContain("</html>");
        expect(html).toContain("<h1>");
        expect(html).toContain("My Report");
        expect(html).toContain("status");
    });
});
