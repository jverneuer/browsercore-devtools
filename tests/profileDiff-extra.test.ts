import { describe, expect, it } from "vitest";
import { registerProfile, type BrowserProfile, type ProfileId } from "@browsercore/profiles";
import { diffProfiles } from "../src/diff/profileDiff.js";

function baseProfile(id: string, overrides: Partial<BrowserProfile> = {}): BrowserProfile {
    return {
        id: id as ProfileId,
        name: id,
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
        http1: {
            defaultHeaders: { "user-agent": "test/1.0" },
            headerOrder: ["user-agent"],
            connection: "keep-alive" as const,
            acceptEncoding: "gzip",
        },
        ...overrides,
    };
}

describe("diffProfiles — Date and mixed-type comparisons", () => {
    it("reports a Date differing from a non-Date value at the same path", () => {
        // leafEqual(Date, number) is false and the Date-vs-anything branch fires.
        const a = { ...baseProfile("date-mix-a"), stamp: new Date("2026-01-01T00:00:00Z") } as unknown as BrowserProfile;
        const b = { ...baseProfile("date-mix-b"), stamp: 1_000_000 } as unknown as BrowserProfile;
        registerProfile(a);
        registerProfile(b);
        const diff = diffProfiles(a.id, b.id);
        const entry = diff.differences.find((d) => d.path === "stamp");
        expect(entry).toBeDefined();
        expect(entry!.a).toBeInstanceOf(Date);
        expect(entry!.b).toBe(1_000_000);
    });

    it("treats equal timestamps (different Date instances) as equal", () => {
        const t = new Date("2026-06-15T12:00:00Z").getTime();
        const a = { ...baseProfile("date-eq-a"), at: new Date(t) } as unknown as BrowserProfile;
        const b = { ...baseProfile("date-eq-b"), at: new Date(t) } as unknown as BrowserProfile;
        registerProfile(a);
        registerProfile(b);
        expect(diffProfiles(a.id, b.id).differences.some((d) => d.path === "at")).toBe(false);
    });
});

describe("diffProfiles — path ordering and nesting", () => {
    it("emits object-key differences in sorted key order", () => {
        // Deliberately out-of-insertion-order keys; the diff must walk them sorted.
        const a = {
            ...baseProfile("order-a"),
            block: { zeta: 1, alpha: 2, mike: 3 } as unknown,
        } as unknown as BrowserProfile;
        const b = {
            ...baseProfile("order-b"),
            block: { zeta: 10, alpha: 20, mike: 30 } as unknown,
        } as unknown as BrowserProfile;
        registerProfile(a);
        registerProfile(b);
        const diff = diffProfiles(a.id, b.id);
        const paths = diff.differences.filter((d) => d.path.startsWith("block/")).map((d) => d.path);
        expect(paths).toEqual(["block/alpha", "block/mike", "block/zeta"]);
    });

    it("recurses into arrays of objects and reports the differing inner field", () => {
        const a = {
            ...baseProfile("nest-a"),
            items: [{ v: 1 }, { v: 2 }, { v: 3 }] as unknown,
        } as unknown as BrowserProfile;
        const b = {
            ...baseProfile("nest-b"),
            items: [{ v: 1 }, { v: 99 }, { v: 3 }] as unknown,
        } as unknown as BrowserProfile;
        registerProfile(a);
        registerProfile(b);
        const diff = diffProfiles(a.id, b.id);
        expect(diff.differences.some((d) => d.path === "items/1/v")).toBe(true);
    });

    it("reports an array element that is an added object as <missing> on side B", () => {
        const a = {
            ...baseProfile("arr-grow-a"),
            items: [{ v: 1 }] as unknown,
        } as unknown as BrowserProfile;
        const b = {
            ...baseProfile("arr-grow-b"),
            items: [{ v: 1 }, { v: 2 }] as unknown,
        } as unknown as BrowserProfile;
        registerProfile(a);
        registerProfile(b);
        const diff = diffProfiles(a.id, b.id);
        const entry = diff.differences.find((d) => d.path === "items/1");
        expect(entry).toBeDefined();
        expect(entry!.a).toBe("<missing>");
        expect(entry!.b).toMatchObject({ v: 2 });
    });
});

describe("diffProfiles — result shape contract", () => {
    it("echoes back the exact profile ids it was given", () => {
        const a = baseProfile("echo-a");
        const b = baseProfile("echo-b", { version: "9.9" });
        registerProfile(a);
        registerProfile(b);
        const diff = diffProfiles("echo-a" as ProfileId, "echo-b" as ProfileId);
        expect(diff.profileA).toBe("echo-a");
        expect(diff.profileB).toBe("echo-b");
    });

    it("differences is a readonly array snapshot (immutable from the caller view)", () => {
        const a = baseProfile("snap-a");
        const b = baseProfile("snap-b", { version: "2.0" });
        registerProfile(a);
        registerProfile(b);
        const diff = diffProfiles(a.id, b.id);
        expect(Array.isArray(diff.differences)).toBe(true);
        // The same ids diffed twice yields equal, independent arrays.
        const again = diffProfiles(a.id, b.id);
        expect(again.differences).toEqual(diff.differences);
        expect(again.differences).not.toBe(diff.differences);
    });
});
