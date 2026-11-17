import { describe, expect, it } from "vitest";
import { assertNever, createId } from "../src/utils.js";

describe("assertNever", () => {
    it("throws an Error describing the unexpected value", () => {
        // Cast through unknown to simulate an unreachable branch at runtime.
        expect(() => assertNever("oops" as never)).toThrow(/Unexpected value/u);
    });

    it("stringifies the unexpected value in the message", () => {
        let caught: Error | undefined;
        try {
            assertNever(42 as never);
        } catch (err) {
            if (err instanceof Error) {
                caught = err;
            }
        }
        // Fails when assertNever did not throw (or threw a non-Error).
        expect(caught?.message).toContain("42");
    });
});

describe("createId", () => {
    it("uses the insp prefix by default", () => {
        expect(createId().startsWith("insp_")).toBe(true);
    });

    it("honors a custom prefix", () => {
        expect(createId("insp").startsWith("insp_")).toBe(true);
    });

    it("produces unique ids across calls", () => {
        const ids = new Set(Array.from({ length: 50 }, () => createId()));
        expect(ids.size).toBe(50);
    });
});
