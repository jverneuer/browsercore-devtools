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

    it("returns a string for a top-level undefined value", () => {
        // JSON.stringify(undefined) yields the undefined *value*, which would
        // violate the declared `: string` return type; the `?? "null"` guard
        // canonicalizes it.
        const out = exportToJson(undefined);
        expect(typeof out).toBe("string");
        expect(out).toBe("null");
    });

    it("returns a string for a top-level symbol", () => {
        expect(typeof exportToJson(Symbol("s"))).toBe("string");
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

    it("renders a bigint with the 'num' CSS class", () => {
        // renderHtmlValue now folds bigint into the numeric class alongside number.
        const html = exportToHtml("T", { big: 10n });
        expect(html).toContain(">10<");
        const row = html.match(/big[^]*?\n/)?.[0] ?? html;
        expect(row).toContain("num");
        expect(row).not.toContain("bool");
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
    // Symbol and function values fall through to the fallback branch, which now
    // calls escapeHtml(String(value)). String() renders symbols as "Symbol(s)"
    // and functions as their source string, so the fallback renders these
    // gracefully instead of crashing (it previously passed undefined into
    // escapeHtml because JSON.stringify(Symbol|function) returns undefined).

    it("renders a top-level symbol value without throwing", () => {
        const html = exportToHtml("T", Symbol("s"));
        expect(html).toContain("Symbol(s)");
        expect(html).toContain("<!DOCTYPE html>");
    });

    it("renders an object containing a symbol value without throwing", () => {
        // A realistic input shape: a plain object whose property value is a symbol.
        const html = exportToHtml("T", { flag: Symbol("x") });
        expect(html).toContain("Symbol(x)");
    });

    it("renders a top-level function value without throwing", () => {
        const html = exportToHtml("T", () => 1);
        // The function is rendered as its source string and produces a valid row.
        expect(html).toContain("<!DOCTYPE html>");
        expect(html).toContain("class=\"any\"");
    });

    it("renders a symbol with no description as Symbol()", () => {
        // Symbol() (no descriptor) has description === undefined, so the
        // `value.description ?? ""` fallback renders the empty parens.
        const html = exportToHtml("T", Symbol());
        expect(html).toContain("Symbol()");
        expect(html).toContain("class=\"any\"");
    });
});
