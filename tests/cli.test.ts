import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { dispatch } from "../src/cli.js";
import { registerProfile } from "@browsercore/profiles";
import { writeFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { makeMinimalCert } from "./_testhelpers.js";

const TMP = join(tmpdir(), `devtools-cli-${process.pid}`);

beforeAll(() => {
    mkdirSync(TMP, { recursive: true });
});

afterAll(() => {
    rmSync(TMP, { recursive: true, force: true });
});

/** Collect lines written by a dispatch call. */
function run(argv: ReadonlyArray<string>): string[] {
    const lines: string[] = [];
    dispatch(argv, (line) => lines.push(line));
    return lines;
}

describe("_dispatch", () => {
    it("prints help when no command is given", () => {
        const lines = run(["node", "network-devtools"]);
        expect(lines.some((l) => l.includes("Usage:"))).toBe(true);
        expect(lines.some((l) => l.includes("inspect"))).toBe(true);
    });

    it("prints help for --help", () => {
        const lines = run(["node", "network-devtools", "--help"]);
        expect(lines.some((l) => l.includes("Commands:"))).toBe(true);
    });

    it("prints help for -h", () => {
        const lines = run(["node", "network-devtools", "-h"]);
        expect(lines.some((l) => l.includes("Usage:"))).toBe(true);
    });

    it("throws on an unknown command", () => {
        expect(() => run(["node", "network-devtools", "bogus"])).toThrow(/Unknown command 'bogus'/);
    });

    it("inspect summarizes a capture file", () => {
        const capturePath = join(TMP, "capture.bin");
        writeFileSync(capturePath, new Uint8Array([0x01, 0x02, 0x03, 0x04]));
        const lines = run(["node", "network-devtools", "inspect", capturePath]);
        expect(lines.some((l) => l.startsWith("Session "))).toBe(true);
        expect(lines.some((l) => l.includes("frames: 1"))).toBe(true);
        expect(lines.some((l) => l.includes("bytes:  4"))).toBe(true);
    });

    it("inspect reports a missing path", () => {
        const lines = run(["node", "network-devtools", "inspect"]);
        expect(lines[0]).toBe("inspect: missing <capture> path");
    });

    it("tls visualizes a capture file", () => {
        const capturePath = join(TMP, "tls.bin");
        writeFileSync(capturePath, new Uint8Array([0x16, 0x03, 0x03, 0x00, 0x00]));
        const lines = run(["node", "network-devtools", "tls", capturePath]);
        const out = lines.join("\n");
        expect(out).toContain("TLS");
    });

    it("tls reports a missing path", () => {
        const lines = run(["node", "network-devtools", "tls"]);
        expect(lines[0]).toBe("tls: missing <capture> path");
    });

    it("http2 visualizes a capture file", () => {
        const capturePath = join(TMP, "http2.bin");
        writeFileSync(capturePath, new Uint8Array(9));
        const lines = run(["node", "network-devtools", "http2", capturePath]);
        const out = lines.join("\n");
        expect(out).toContain("HTTP/2");
    });

    it("http2 reports a missing path", () => {
        const lines = run(["node", "network-devtools", "http2"]);
        expect(lines[0]).toBe("http2: missing <capture> path");
    });

    it("diff reports missing profile ids", () => {
        const lines = run(["node", "network-devtools", "diff", "only-one"]);
        expect(lines[0]).toBe("diff: requires <profile-a> <profile-b>");
    });

    it("diff reports changes between two registered profiles", () => {
        const a = {
            id: "cli-diff-a",
            name: "a",
            version: "1.0",
            tls: {
                cipherSuites: ["TLS_AES_128_GCM_SHA256"],
                extensionOrder: [],
                supportedVersions: ["TLS 1.3"],
                keyShareGroups: ["x25519"],
                signatureAlgorithms: ["ecdsa_secp256r1_sha256"],
                grease: true,
            },
            http2: { settings: {}, initialWindowSize: 6291456, maxFrameSize: 16384, headerTableSize: 65536, weight: 255 },
            http1: { defaultHeaders: { "user-agent": "a/1.0" }, headerOrder: ["user-agent"], connection: "keep-alive" as const, acceptEncoding: "gzip" },
        };
        const b = { ...a, id: "cli-diff-b", version: "2.0" };
        registerProfile(a as never);
        registerProfile(b as never);
        const lines = run(["node", "network-devtools", "diff", "cli-diff-a", "cli-diff-b"]);
        const out = lines.join("\n");
        expect(out).toContain("Diff cli-diff-a vs cli-diff-b");
        expect(out).toContain("version");
    });

    it("cert inspects a PEM certificate file", () => {
        const certPath = join(TMP, "cert.pem");
        writeFileSync(certPath, makeMinimalCert());
        const lines = run(["node", "network-devtools", "cert", certPath]);
        const out = lines.join("\n");
        expect(out).toContain("Subject:");
        expect(out).toContain("Issuer:");
        expect(out).toContain("Valid:");
        expect(out).toContain("SAN:");
        expect(out).toContain("SHA-256:");
    });

    it("cert reports a missing path", () => {
        const lines = run(["node", "network-devtools", "cert"]);
        expect(lines[0]).toBe("cert: missing <cert> path");
    });

    it("bench prints a stub message", () => {
        const lines = run(["node", "network-devtools", "bench"]);
        expect(lines[0]).toContain("stub");
    });
});
