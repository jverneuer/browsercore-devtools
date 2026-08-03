import { describe, expect, it } from "vitest";
import { exportToJson, exportToHtml } from "../src/exporters.js";

describe("exportToJson — round-trips and edge values", () => {
    it("round-trips nested objects, arrays, null, and numbers through JSON.parse", () => {
        const data = { a: 1, b: [2, 3], c: { d: null, e: true }, f: "str" };
        expect(JSON.parse(exportToJson(data))).toEqual(data);
    });

    it("round-trips an empty object and empty array", () => {
        expect(JSON.parse(exportToJson({}))).toEqual({});
        expect(JSON.parse(exportToJson([]))).toEqual([]);
    });

    it("BUG: returns undefined (not a string) for a top-level undefined value", () => {
        // JSON.stringify(undefined) yields the undefined *value*, so the declared
        // `: string` return type is violated. Pinned current behavior; a fix should
        // decide on a canonical representation (e.g. "null" or "undefined").
        const out = exportToJson(undefined);
        expect(out).toBeUndefined();
    });

    it("BUG: returns undefined (not a string) for a top-level symbol", () => {
        expect(exportToJson(Symbol("s"))).toBeUndefined();
    });
});

describe("exportToHtml — scalar and composite rendering", () => {
    it("renders falsy primitives (0, false, empty string) distinctly", () => {
        const html = exportToHtml("T", { zero: 0, flag: false, empty: "" });
        // Labels render unquoted as a prefix ("zero: "), values inside spans.
        expect(html).toContain("zero:");
        expect(html).toContain(">0<");
        expect(html).toContain("flag:");
        expect(html).toContain(">false<");
        expect(html).toContain("empty:");
        // Empty string still renders an empty quoted span.
        expect(html).toContain('""');
    });

    it("renders a top-level empty array as an empty list", () => {
        const html = exportToHtml("T", []);
        expect(html).toContain("<ul></ul>");
    });

    it("renders nested arrays recursively", () => {
        const html = exportToHtml("T", [[1, 2], [3]]);
        expect(html).toContain("<ul>");
        // Both inner numbers appear in nested list items.
        expect(html).toContain("1");
        expect(html).toContain("3");
    });

    it("renders a Map nested inside an object as labeled rows", () => {
        const html = exportToHtml("T", { headers: new Map([["accept", "*/*"]]) });
        expect(html).toContain("accept");
        expect(html).toContain("*/*");
    });

    it("renders a nested object inside an array", () => {
        const html = exportToHtml("T", [{ name: "inner" }]);
        expect(html).toContain("name");
        expect(html).toContain("inner");
    });

    it("escapes every special HTML character in both title and string values", () => {
        const html = exportToHtml(`<a>"&'</a>`, { k: `<b>"&'</b>` });
        // No raw injection vectors remain.
        expect(html).not.toMatch(/<a>|<b>/);
        expect(html).toContain("&lt;a&gt;");
        expect(html).toContain("&lt;b&gt;");
        expect(html).toContain("&quot;");
        expect(html).toContain("&#39;");
        expect(html).toContain("&amp;");
    });

    it("BUG: renders a bigint with the 'bool' CSS class instead of 'num'", () => {
        // renderHtmlValue groups number|boolean|bigint but only distinguishes
        // `typeof === "number"` (-> num) from everything else (-> bool), so a bigint
        // is mislabeled. Pinned current behavior; a fix should assign bigint its own
        // class (or fold it into num) and update this assertion.
        const html = exportToHtml("T", { big: 10n });
        expect(html).toContain(">10<");
        // The bigint row is tagged with the boolean style.
        const row = html.match(/big[^]*?\n/)?.[0] ?? html;
        expect(row).toContain("bool");
        expect(row).not.toContain("num");
    });

    it("renders a deep structure without truncation or crashing", () => {
        const deep = { a: { b: { c: { d: { e: "deep" } } } } };
        const html = exportToHtml("T", deep);
        expect(html).toContain("deep");
        expect(html).toContain("<!DOCTYPE html>");
        expect(html).toContain("</html>");
    });
});

describe("exportToHtml — values that defeat serialization", () => {
    // Symbol and function values fall through to the fallback branch, which calls
    // escapeHtml(JSON.stringify(value)). JSON.stringify of a symbol/function
    // returns the undefined value, and escapeHtml(undefined) throws a TypeError
    // because it calls String.prototype.replaceAll on undefined. The fallback was
    // clearly intended to render these gracefully (its comment says so). Reported
    // as a source bug; the assertions below pin the current behavior.

    it("BUG: throws a TypeError for a top-level symbol value", () => {
        // JSON.stringify(Symbol) -> undefined; escapeHtml(undefined) -> TypeError.
        expect(() => exportToHtml("T", Symbol("s"))).toThrow(TypeError);
    });

    it("BUG: throws a TypeError for an object containing a symbol value", () => {
        // A realistic input shape: a plain object whose property value is a symbol.
        expect(() => exportToHtml("T", { flag: Symbol("x") })).toThrow(TypeError);
    });

    it("BUG: throws a TypeError for a top-level function value", () => {
        expect(() => exportToHtml("T", () => 1)).toThrow(TypeError);
    });

    // Desired (post-fix) behavior — skipped until the fallback renders these
    // gracefully instead of crashing.
    it.skip("renders a top-level symbol value without throwing (desired)", () => {
        expect(() => exportToHtml("T", Symbol("s"))).not.toThrow();
    });
});
