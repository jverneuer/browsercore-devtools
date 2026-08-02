import { describe, expect, it } from "vitest";
import { registerProfile, type BrowserProfile, type ProfileId } from "@browsercore/profiles";
import { diffProfiles } from "../src/diff/profileDiff.js";
import { ProfileDiffError } from "../src/errors.js";

function makeProfile(id: string, overrides: Partial<BrowserProfile> = {}): BrowserProfile {
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
        ...overrides,
    };
}

describe("diffProfiles", () => {
    it("reports no differences for identical profiles", () => {
        const p = makeProfile("identical-a");
        registerProfile(p);
        const diff = diffProfiles(p.id, p.id);
        expect(diff.differences).toEqual([]);
        expect(diff.profileA).toBe(p.id);
        expect(diff.profileB).toBe(p.id);
    });

    it("reports a changed scalar field", () => {
        const a = makeProfile("scalar-a");
        const b = makeProfile("scalar-b", { version: "2.0" });
        registerProfile(a);
        registerProfile(b);
        const diff = diffProfiles(a.id, b.id);
        expect(diff.differences.length).toBeGreaterThan(0);
        expect(diff.differences.some((d) => d.path === "version")).toBe(true);
    });

    it("reports an added array element as a numeric path", () => {
        const a = makeProfile("arr-a", { tls: { ...makeProfile("x").tls, cipherSuites: ["TLS_AES_128_GCM_SHA256"] } });
        const b = makeProfile("arr-b", {
            tls: { ...makeProfile("x").tls, cipherSuites: ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"] },
        });
        registerProfile(a);
        registerProfile(b);
        const diff = diffProfiles(a.id, b.id);
        expect(diff.differences.some((d) => d.path === "tls/cipherSuites/1")).toBe(true);
    });

    it("reports a missing child on side A", () => {
        const a = makeProfile("miss-a", { http1: undefined });
        const b = makeProfile("miss-b");
        registerProfile(a);
        registerProfile(b);
        const diff = diffProfiles(a.id, b.id);
        const entry = diff.differences.find((d) => d.path === "http1");
        expect(entry).toBeDefined();
        expect(entry!.a).toBe("<missing>");
    });

    it("reports a missing child on side B", () => {
        const a = makeProfile("miss-ba");
        const b = makeProfile("miss-bb", { http1: undefined });
        registerProfile(a);
        registerProfile(b);
        const diff = diffProfiles(a.id, b.id);
        const entry = diff.differences.find((d) => d.path === "http1");
        expect(entry).toBeDefined();
        expect(entry!.b).toBe("<missing>");
    });

    it("reports a missing array element with <missing>", () => {
        const a = makeProfile("short-a", { tls: { ...makeProfile("x").tls, cipherSuites: ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"] } });
        const b = makeProfile("short-b", { tls: { ...makeProfile("x").tls, cipherSuites: ["TLS_AES_128_GCM_SHA256"] } });
        registerProfile(a);
        registerProfile(b);
        const diff = diffProfiles(a.id, b.id);
        const entry = diff.differences.find((d) => d.path === "tls/cipherSuites/1");
        expect(entry).toBeDefined();
        expect(entry!.b).toBe("<missing>");
    });

    it("treats equal Date values as equal (no diff)", () => {
        const day = new Date("2026-01-01T00:00:00Z");
        const a = makeProfile("date-a", { tls: { ...makeProfile("x").tls, cipherSuites: [] }, http2: undefined, http1: undefined } as Partial<BrowserProfile>);
        // Inject a Date field by building a minimal custom profile.
        const withDate = {
            ...makeProfile("date-equal-a"),
            expires: day,
        };
        const withSameDate = {
            ...makeProfile("date-equal-b"),
            expires: new Date(day.getTime()),
        };
        registerProfile(withDate as unknown as BrowserProfile);
        registerProfile(withSameDate as unknown as BrowserProfile);
        const diff = diffProfiles((withDate as BrowserProfile).id, (withSameDate as BrowserProfile).id);
        expect(diff.differences.some((d) => d.path === "expires")).toBe(false);
    });

    it("reports differing Date values", () => {
        const a = { ...makeProfile("date-diff-a"), expires: new Date("2026-01-01T00:00:00Z") } as unknown as BrowserProfile;
        const b = { ...makeProfile("date-diff-b"), expires: new Date("2026-06-01T00:00:00Z") } as unknown as BrowserProfile;
        registerProfile(a);
        registerProfile(b);
        const diff = diffProfiles(a.id, b.id);
        expect(diff.differences.some((d) => d.path === "expires")).toBe(true);
    });

    it("throws ProfileDiffError for an unknown profile id", () => {
        expect(() => diffProfiles("does-not-exist" as ProfileId, "also-missing" as ProfileId)).toThrow(ProfileDiffError);
    });

    it("wraps the UnknownProfileError message", () => {
        try {
            diffProfiles("does-not-exist" as ProfileId, "also-missing" as ProfileId);
        } catch (err) {
            expect(err).toBeInstanceOf(ProfileDiffError);
            expect((err as ProfileDiffError).message).toContain("Unknown browser profile");
            return;
        }
        throw new Error("expected to throw");
    });
});
