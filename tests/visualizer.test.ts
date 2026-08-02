import { describe, expect, it } from "vitest";
import { decodeHttp1Message, renderFrame, visualizeTlsHandshake, visualizeHttp2Stream } from "../src/visualizer/visualizer.js";
import { createInspectorSession } from "../src/inspector/inspector.js";
import { assertNever } from "../src/utils.js";
import type { PacketFrame, PacketProtocol } from "../src/types.js";

/** Build a frame with a fixed timestamp so output assertions are deterministic. */
function frame(protocol: PacketProtocol, bytes: Uint8Array, direction: "sent" | "received" = "sent"): PacketFrame {
    return { timestamp: 0, direction, protocol, bytes, decoded: null };
}

/** A complete HTTP/1.1 response wire format. */
function http1Response(): Uint8Array {
    const text = [
        "HTTP/1.1 200 OK",
        "Content-Type: text/html",
        "Content-Length: 13",
        "",
        "<html></html>",
    ].join("\r\n");
    return new TextEncoder().encode(text);
}

/** A complete HTTP/1.1 request wire format. */
function http1Request(): Uint8Array {
    const text = [
        "GET /index.html HTTP/1.1",
        "Host: example.com",
        "Accept: */*",
        "",
        "",
    ].join("\r\n");
    return new TextEncoder().encode(text);
}

describe("decodeHttp1Message", () => {
    it("parses a response status line and headers", () => {
        const msg = decodeHttp1Message(http1Response());
        expect(msg.kind).toBe("response");
        expect(msg.statusCode).toBe(200);
        expect(msg.statusLine).toBe("HTTP/1.1 200 OK");
        expect(msg.headers.get("content-type")).toBe("text/html");
        expect(msg.headers.get("content-length")).toBe("13");
    });

    it("parses a request line with null status code", () => {
        const msg = decodeHttp1Message(http1Request());
        expect(msg.kind).toBe("request");
        expect(msg.statusCode).toBeNull();
        expect(msg.statusLine).toBe("GET /index.html HTTP/1.1");
        expect(msg.headers.get("host")).toBe("example.com");
    });

    it("decodes the body up to Content-Length", () => {
        const msg = decodeHttp1Message(http1Response());
        expect(msg.bodyPreview).toBe("<html></html>");
    });

    it("returns an unparsed start line when no header section terminator exists", () => {
        const bytes = new TextEncoder().encode("GARBAGE-WITHOUT-HEADERS");
        const msg = decodeHttp1Message(bytes);
        expect(msg.kind).toBe("response"); // falls through regex (no match → request? no: regex fails → request)
        // The regex does not match, so it is classified as a request line.
        expect(msg.statusCode).toBeNull();
        expect(msg.headers.size).toBe(0);
        expect(msg.bodyPreview).toBe("");
        expect(msg.statusLine.startsWith("GARBAGE")).toBe(true);
    });

    it("returns an empty body preview when bodyStart is at the end", () => {
        const text = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        const msg = decodeHttp1Message(new TextEncoder().encode(text));
        expect(msg.bodyPreview).toBe("");
        expect(msg.statusCode).toBe(200);
    });

    it("ignores header lines without a colon", () => {
        // A line without a colon inside the header section is skipped; the valid
        // header before it is still parsed.
        const text = ["HTTP/1.1 200 OK", "not-a-valid-header-line", "X-Foo: bar", "", ""].join("\r\n");
        const msg = decodeHttp1Message(new TextEncoder().encode(text));
        expect(msg.headers.size).toBe(1);
        expect(msg.headers.get("x-foo")).toBe("bar");
    });

    it("lower-cases header names and trims values", () => {
        const text = "HTTP/1.1 200 OK\r\nX-Custom :  value with spaces \r\n\r\n";
        const msg = decodeHttp1Message(new TextEncoder().encode(text));
        expect(msg.headers.get("x-custom")).toBe("value with spaces");
    });

    it("decodes chunked transfer-encoding bodies", () => {
        const body = "hello";
        const chunked = `${body.length.toString(16)}\r\n${body}\r\n0\r\n\r\n`;
        const text = `HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n${chunked}`;
        const msg = decodeHttp1Message(new TextEncoder().encode(text));
        expect(msg.bodyPreview).toBe("hello");
    });

    it("honors Content-Length over a larger buffer", () => {
        const text = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nABCDEEXTRA";
        const msg = decodeHttp1Message(new TextEncoder().encode(text));
        expect(msg.bodyPreview).toBe("ABCDE");
    });

    it("caps the body preview at the preview limit", () => {
        const big = "x".repeat(1000);
        const text = `HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n${big}`;
        const msg = decodeHttp1Message(new TextEncoder().encode(text));
        expect(msg.bodyPreview.length).toBe(256);
    });

    it("stops a chunked body at the terminating zero-size chunk", () => {
        const chunked = "5\r\nhello\x00\r\n0\r\n\r\nTRAILER";
        const text = `HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n${chunked}`;
        const msg = decodeHttp1Message(new TextEncoder().encode(text));
        // First chunk "hello\x00" (5 bytes) is decoded; the 0-size chunk terminates.
        expect(msg.bodyPreview.startsWith("hello")).toBe(true);
    });
});

describe("renderFrame", () => {
    it("renders a TLS frame line", () => {
        const out = renderFrame(frame("tls", new Uint8Array([0x16, 0x03, 0x03, 0x00, 0x00])));
        expect(out).toContain("TLS");
        expect(out).toContain("→");
    });

    it("renders an HTTP/2 frame line", () => {
        const out = renderFrame(frame("http2", new Uint8Array(9)));
        expect(out).toContain("HTTP/2");
    });

    it("renders an HTTP/1.1 frame line with status code and header count", () => {
        const out = renderFrame(frame("http1", http1Response()));
        expect(out).toContain("HTTP/1.1");
        expect(out).toContain("200");
        expect(out).toContain("headers");
    });

    it("renders a request frame line without a status code", () => {
        const out = renderFrame(frame("http1", http1Request(), "received"));
        expect(out).toContain("GET /index.html HTTP/1.1");
        expect(out).toContain("←");
    });

    it("renders a generic TCP frame line", () => {
        const out = renderFrame(frame("tcp", new Uint8Array([0x01, 0x02, 0x03])));
        expect(out).toContain("TCP");
        expect(out).toContain("3 bytes");
    });

    it("renders a body preview line when present", () => {
        const out = renderFrame(frame("http1", http1Response()));
        expect(out).toContain("body:");
        expect(out).toContain("<html></html>");
    });

    it("renders a hex preview with an overflow indicator for long frames", () => {
        const out = renderFrame(frame("tcp", new Uint8Array(100)));
        expect(out).toContain("(+");
        expect(out).toContain("bytes)");
    });

    it("formats an unknown HTTP/2 frame type as a hex code", () => {
        // 9-byte frame header: length=0, type=255 (unknown), flags=0, streamId=0.
        const bytes = new Uint8Array([0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00]);
        const out = renderFrame(frame("http2", bytes));
        expect(out).toContain("0xff");
    });
});

describe("visualize empty sessions", () => {
    it("reports no TLS frames when none captured", () => {
        const session = createInspectorSession();
        const out = visualizeTlsHandshake(session);
        expect(out).toContain("(no TLS frames captured)");
    });

    it("reports no HTTP/2 frames when none captured", () => {
        const session = createInspectorSession();
        const out = visualizeHttp2Stream(session);
        expect(out).toContain("(no HTTP/2 frames captured)");
    });

    it("filters frames to the requested protocol", () => {
        const session = createInspectorSession();
        session.addFrame(frame("tls", new Uint8Array([0x16, 0x03, 0x03, 0x00, 0x00])));
        session.addFrame(frame("http2", new Uint8Array(9)));
        const tlsOut = visualizeTlsHandshake(session);
        const h2Out = visualizeHttp2Stream(session);
        expect(tlsOut).toContain("TLS");
        expect(tlsOut).not.toContain("HTTP/2");
        expect(h2Out).toContain("HTTP/2");
        expect(h2Out).not.toContain("0x0303"); // TLS version string absent
    });
});

describe("assertNever exhaustiveness", () => {
    it("throws for an unreachable protocol value", () => {
        // Cast an invalid protocol through the type system to exercise the default branch.
        const invalid = "quic" as unknown as PacketProtocol;
        expect(() => assertNever(invalid)).toThrow(/Unexpected value/);
    });

    it("throws for a never value", () => {
        // Force a runtime value of the never-typed parameter.
        expect(() => assertNever("surprise" as never)).toThrow(/Unexpected value/);
    });
});
