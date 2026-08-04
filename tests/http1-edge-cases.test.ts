import { describe, expect, it } from "vitest";
import { decodeHttp1Message } from "../src/visualizer/http1.js";

const ENC = new TextEncoder();

/** Wrap raw bytes as an HTTP/1.1 response with the given headers. */
function response(headers: string[], body: string, statusLine = "HTTP/1.1 200 OK"): Uint8Array {
    const head = [statusLine, ...headers, "", body].join("\r\n");
    return ENC.encode(head);
}

describe("decodeHttp1Message — chunked transfer-encoding", () => {
    it("concatenates multiple chunks into the body preview", () => {
        const chunked = "5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n";
        const msg = decodeHttp1Message(ENC.encode(`HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n${chunked}`));
        expect(msg.bodyPreview).toBe("helloworld");
    });

    it("returns an empty body when only the terminating zero-size chunk is present", () => {
        const msg = decodeHttp1Message(ENC.encode(`HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n`));
        expect(msg.bodyPreview).toBe("");
    });

    it("returns an empty body when no chunk-size line terminator (CRLF) is found", () => {
        // A size line with no CRLF terminator -> decodeChunkedBody bails immediately.
        const msg = decodeHttp1Message(ENC.encode(`HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5hello`));
        expect(msg.bodyPreview).toBe("");
    });

    it("stops decoding when the chunk-size line is not hexadecimal", () => {
        // "xx" is not a valid hex size -> decode stops with an empty buffer.
        const msg = decodeHttp1Message(
            ENC.encode(`HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nxx\r\nhello\r\n0\r\n\r\n`),
        );
        expect(msg.bodyPreview).toBe("");
    });

    it("stops decoding when a chunk's data runs past the end of the buffer (truncated)", () => {
        // size line claims 0xff bytes but only a few follow -> dataEnd > length -> stop.
        const msg = decodeHttp1Message(ENC.encode(`HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nff\r\nshort`));
        expect(msg.bodyPreview).toBe("");
    });

    it("ignores trailing bytes after the zero-size terminator", () => {
        const chunked = "5\r\nhello\r\n0\r\n\r\nTRAILER-IGNORED";
        const msg = decodeHttp1Message(ENC.encode(`HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n${chunked}`));
        expect(msg.bodyPreview).toBe("hello");
    });
});

describe("decodeHttp1Message — Content-Length handling", () => {
    it("ignores a non-numeric Content-Length and surfaces the remaining body", () => {
        const msg = decodeHttp1Message(response(["Content-Length: abc"], "ABCDE"));
        // NaN Content-Length falls through; whole remaining body is previewed (capped at 256).
        expect(msg.bodyPreview).toBe("ABCDE");
    });

    it("ignores a negative Content-Length and surfaces the remaining body", () => {
        const msg = decodeHttp1Message(response(["Content-Length: -3"], "ABCDE"));
        expect(msg.bodyPreview).toBe("ABCDE");
    });

    it("clamps Content-Length to the available body bytes", () => {
        const msg = decodeHttp1Message(response(["Content-Length: 100"], "ABC"));
        expect(msg.bodyPreview).toBe("ABC");
    });

    it("prefers chunked decoding over Content-Length when both are present", () => {
        // RFC 7230: chunked overrides Content-Length. The 5-byte "hello" chunk wins
        // over the (deliberately wrong) Content-Length: 2.
        const chunked = "5\r\nhello\r\n0\r\n\r\n";
        const msg = decodeHttp1Message(
            ENC.encode(`HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n${chunked}`),
        );
        expect(msg.bodyPreview).toBe("hello");
    });
});

describe("decodeHttp1Message — start-line & header edge cases", () => {
    it("truncates an unterminated start line to 120 characters", () => {
        // No \r\n\r\n terminator -> the raw text (capped at 120) becomes the status line.
        const garbage = "X".repeat(300);
        const msg = decodeHttp1Message(ENC.encode(garbage));
        expect(msg.statusLine.length).toBe(120);
        expect(msg.headers.size).toBe(0);
        expect(msg.bodyPreview).toBe("");
        // No header terminator means the bytes are treated as a bare start line;
        // the regex won't match, so there is no status code.
        expect(msg.statusCode).toBeNull();
    });

    it("parses a response with a non-standard status code (e.g. 418)", () => {
        const msg = decodeHttp1Message(response(["Content-Length: 0"], "", "HTTP/1.1 418 I'm a teapot"));
        expect(msg.kind).toBe("response");
        expect(msg.statusCode).toBe(418);
        expect(msg.statusLine).toBe("HTTP/1.1 418 I'm a teapot");
    });

    it("overwrites duplicate headers with the last value", () => {
        const msg = decodeHttp1Message(
            ENC.encode("HTTP/1.1 200 OK\r\nX-Dup: one\r\nX-Dup: two\r\nContent-Length: 0\r\n\r\n"),
        );
        expect(msg.headers.get("x-dup")).toBe("two");
    });

    it("parses a request with a body framed by Content-Length", () => {
        const text = "POST /submit HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 7\r\n\r\npayload";
        const msg = decodeHttp1Message(ENC.encode(text));
        expect(msg.kind).toBe("request");
        expect(msg.statusCode).toBeNull();
        expect(msg.statusLine).toBe("POST /submit HTTP/1.1");
        expect(msg.headers.get("content-length")).toBe("7");
        expect(msg.bodyPreview).toBe("payload");
    });

    it("renders an HTTP/0.9-style status line without a code as a request", () => {
        // The regex requires HTTP/x.y; a bare line that misses it is classified as a request.
        const msg = decodeHttp1Message(ENC.encode("SOMETEXT value\r\nX: y\r\n\r\n"));
        expect(msg.kind).toBe("request");
        expect(msg.statusCode).toBeNull();
    });

    it("previews the body using neither Content-Length nor Transfer-Encoding", () => {
        // With no Content-Length and no Transfer-Encoding, previewHttp1Body takes the
        // else-of-else path: it surfaces a raw slice of the remaining bytes (capped).
        const text = "HTTP/1.1 200 OK\r\n\r\nBODY-WITHOUT-LENGTH";
        const msg = decodeHttp1Message(ENC.encode(text));
        expect(msg.statusCode).toBe(200);
        expect(msg.bodyPreview).toBe("BODY-WITHOUT-LENGTH");
    });
});
