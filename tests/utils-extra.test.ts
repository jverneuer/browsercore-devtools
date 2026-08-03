import { describe, expect, it } from "vitest";
import { assertNever, createId, createInspectorSessionId, toErrorOptions } from "../src/utils.js";

describe("toErrorOptions", () => {
    it("wraps an Error in { cause }", () => {
        const err = new Error("boom");
        expect(toErrorOptions(err)).toEqual({ cause: err });
    });

    it("wraps a subclass of Error", () => {
        class MyErr extends Error {}
        const err = new MyErr("nested");
        expect(toErrorOptions(err)).toEqual({ cause: err });
    });

    it("returns undefined for a non-Error caught value (string)", () => {
        expect(toErrorOptions("a string")).toBeUndefined();
    });

    it("returns undefined for a non-Error caught value (number)", () => {
        expect(toErrorOptions(42)).toBeUndefined();
    });

    it("returns undefined for null and undefined", () => {
        expect(toErrorOptions(null)).toBeUndefined();
        expect(toErrorOptions(undefined)).toBeUndefined();
    });

    it("returns undefined for a plain object that is not an Error instance", () => {
        expect(toErrorOptions({ message: "looks like an error" })).toBeUndefined();
    });
});

describe("createInspectorSessionId", () => {
    it("produces an id with the insp_ brand prefix", () => {
        expect(createInspectorSessionId().startsWith("insp_")).toBe(true);
    });

    it("produces unique ids across many calls", () => {
        const ids = new Set(Array.from({ length: 200 }, () => createInspectorSessionId()));
        expect(ids.size).toBe(200);
    });
});

describe("createId", () => {
    it("accepts the literal insp prefix", () => {
        const id = createId("insp");
        expect(id.startsWith("insp_")).toBe(true);
        // Three underscore-separated segments: prefix, timestamp, random.
        expect(id.split("_").length).toBe(3);
    });

    it("yields distinct random tails across rapid successive calls", () => {
        const ids = Array.from({ length: 100 }, () => createId());
        expect(new Set(ids).size).toBe(100);
    });
});

describe("assertNever", () => {
    it("stringifies objects in the thrown message", () => {
        try {
            assertNever({ unexpected: true } as never);
        } catch (err) {
            expect((err as Error).message).toContain("Unexpected value");
            expect((err as Error).message).toContain("unexpected");
            return;
        }
        throw new Error("expected to throw");
    });

    it("stringifies null without throwing a serialization error", () => {
        try {
            assertNever(null as never);
        } catch (err) {
            expect((err as Error).message).toContain("null");
            return;
        }
        throw new Error("expected to throw");
    });

    it("throws an Error instance (not a string)", () => {
        try {
            assertNever("x" as never);
        } catch (err) {
            expect(err).toBeInstanceOf(Error);
            return;
        }
        throw new Error("expected to throw");
    });
});
