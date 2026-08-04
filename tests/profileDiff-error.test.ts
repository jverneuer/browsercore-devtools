import { describe, expect, it, vi } from "vitest";
import { diffProfiles } from "../src/diff/profileDiff.js";
import { ProfileDiffError } from "../src/errors.js";
import type { ProfileId } from "@browsercore/profiles";

// vi.mock is hoisted above imports, so the mock reference it closes over must be
// created in a vi.hoisted scope (otherwise it runs before the const is initialized).
const { getProfileMock } = vi.hoisted(() => ({ getProfileMock: vi.fn() }));

/**
 * The catch block in diffProfiles has three branches:
 *   1. UnknownProfileError  → wrapped in a new ProfileDiffError (covered by
 *      profileDiff.test.ts, which uses genuinely unknown ids).
 *   2. ProfileDiffError      → rethrown as-is.
 *   3. anything else         → wrapped with a "failed to diff profiles:" message,
 *      using err.message for Errors and String(err) otherwise.
 * Branches 2 and 3 can only be reached if getProfile throws something other than
 * UnknownProfileError — which the real registry never does. So we mock getProfile
 * to throw on demand and assert each branch's contract.
 */
vi.mock("@browsercore/profiles", async (importOriginal) => {
    const actual = await importOriginal<typeof import("@browsercore/profiles")>();
    return {
        ...actual,
        getProfile: getProfileMock,
    };
});

describe("diffProfiles — catch-block error contract", () => {
    it("wraps a generic Error with a 'failed to diff profiles:' message", () => {
        getProfileMock.mockImplementation(() => {
            throw new TypeError("registry corrupted");
        });
        try {
            diffProfiles("a" as ProfileId, "b" as ProfileId);
            throw new Error("expected to throw");
        } catch (err) {
            expect(err).toBeInstanceOf(ProfileDiffError);
            expect((err as ProfileDiffError).message).toContain("failed to diff profiles");
            expect((err as ProfileDiffError).message).toContain("registry corrupted");
        }
    });

    it("rethrows a ProfileDiffError thrown by getProfile as-is", () => {
        const inner = new ProfileDiffError("already wrapped");
        getProfileMock.mockImplementation(() => {
            throw inner;
        });
        try {
            diffProfiles("a" as ProfileId, "b" as ProfileId);
            throw new Error("expected to throw");
        } catch (err) {
            // Branch 2: the error must be the exact same object, not re-wrapped.
            expect(err).toBe(inner);
        }
    });

    it("stringifies a non-Error thrown value via String(err)", () => {
        getProfileMock.mockImplementation(() => {
            throw 404;
        });
        try {
            diffProfiles("a" as ProfileId, "b" as ProfileId);
            throw new Error("expected to throw");
        } catch (err) {
            expect(err).toBeInstanceOf(ProfileDiffError);
            expect((err as ProfileDiffError).message).toContain("failed to diff profiles");
            expect((err as ProfileDiffError).message).toContain("404");
        }
    });
});
