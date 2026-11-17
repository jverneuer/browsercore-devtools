import { describe, expect, it } from "vitest";
import { exportToJson, exportToHtml } from "../src/exporters.js";

describe("exportToJson", () => {
    it("produces 2-space indented JSON", () => {
        const json = exportToJson({ a: 1, b: [1, 2] });
        expect(JSON.parse(json)).toEqual({ a: 1, b: [1, 2] });
        expect(json).toContain("\n  ");
    });

    it("handles nested objects and null", () => {
        const json = exportToJson({ x: { y: null } });
        expect(JSON.parse(json)).toEqual({ x: { y: null } });
    });
});

describe("exportToHtml", () => {
    it("wraps data in a self-contained document", () => {
        const html = exportToHtml("My Report", { status: "ok", count: 3 });
        expect(html).toContain("<!DOCTYPE html>");
        expect(html).toContain("</html>");
        expect(html).toContain("<h1>");
        expect(html).toContain("My Report");
        expect(html).toContain("status");
        expect(html).toContain("count");
    });

    it("escapes the title for HTML safety", () => {
        const html = exportToHtml("<script>alert(1)</script>", {});
        expect(html).not.toContain("<script>");
        expect(html).toContain("&lt;script&gt;");
    });

    it("escapes string values for HTML safety", () => {
        const html = exportToHtml("T", { key: 'a&b<c>"d\'e' });
        expect(html).toContain("&amp;");
        expect(html).toContain("&lt;");
        expect(html).toContain("&gt;");
        expect(html).toContain("&quot;");
        expect(html).toContain("&#39;");
    });

    it("renders a top-level null value (no label)", () => {
        const html = exportToHtml("T", null);
        expect(html).toContain("null");
    });

    it("renders a top-level undefined value as null (no label)", () => {
        const html = exportToHtml("T", undefined);
        expect(html).toContain("null");
    });

    it("renders a top-level array as a list (no section label)", () => {
        const html = exportToHtml("T", ["a", "b", "c"]);
        expect(html).toContain("<ul>");
        expect(html).toContain("<li>");
        expect(html).toContain("a");
    });

    it("renders a top-level Map with entries as labeled rows (no section label)", () => {
        const html = exportToHtml("T", new Map([["Content-Type", "text/html"], ["Accept", "*/*"]]));
        expect(html).toContain("Content-Type");
        expect(html).toContain("text/html");
        expect(html).toContain("Accept");
    });

    it("renders a top-level empty Map as (empty)", () => {
        const html = exportToHtml("T", new Map<string, string>());
        expect(html).toContain("(empty)");
    });

    it("renders a top-level empty object as (empty)", () => {
        const html = exportToHtml("T", {});
        expect(html).toContain("(empty)");
    });

    it("renders a top-level number with the num class (no label)", () => {
        const html = exportToHtml("T", 42);
        expect(html).toContain("num");
        expect(html).toContain("42");
    });

    it("renders a top-level boolean with the bool class (no label)", () => {
        const html = exportToHtml("T", true);
        expect(html).toContain("bool");
        expect(html).toContain("true");
    });

    it("renders a nested object recursively", () => {
        const html = exportToHtml("T", { outer: { inner: "value" } });
        expect(html).toContain("inner");
        expect(html).toContain("value");
    });
});
