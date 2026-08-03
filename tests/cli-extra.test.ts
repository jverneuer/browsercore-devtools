import { describe, expect, it } from "vitest";
import { dispatch } from "../src/cli.js";
import { ProfileDiffError } from "../src/errors.js";

describe("dispatch — default write sink and error propagation", () => {
    it("uses a no-op write sink when none is provided (no throw, no output)", () => {
        // dispatch() declares a default `write` parameter; calling without it exercises
        // that default branch (an otherwise uncovered function).
        expect(() => dispatch(["node", "network-devtools", "--help"])).not.toThrow();
        expect(() => dispatch(["node", "network-devtools", "bench"])).not.toThrow();
    });

    it("propagates ProfileDiffError when diff targets unknown profile ids", () => {
        // diffProfiles throws for unknown ids; cmdDiff does not swallow it.
        expect(() =>
            dispatch(["node", "network-devtools", "diff", "nope-a", "nope-b"], () => {}),
        ).toThrow(ProfileDiffError);
    });

    it("throws when the diff command is missing only the second profile", () => {
        const lines: string[] = [];
        dispatch(["node", "network-devtools", "diff", "only-a"], (line) => lines.push(line));
        expect(lines[0]).toBe("diff: requires <profile-a> <profile-b>");
    });
});

describe("dispatch — unknown command surface", () => {
    it("includes the offending command verbatim in the thrown message", () => {
        try {
            dispatch(["node", "network-devtools", "totally-unknown"], () => {});
            throw new Error("expected to throw");
        } catch (err) {
            expect((err as Error).message).toContain("totally-unknown");
            expect((err as Error).message).toMatch(/Unknown command/);
        }
    });
});
