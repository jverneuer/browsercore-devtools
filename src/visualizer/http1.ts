/**
 * HTTP/1.1 message decoder — parse raw request/response wire bytes into a
 * readable shape for the visualizer. Self-contained: leans only on the
 * `DecodedHttp1Message` contract from the domain types.
 */

import type { DecodedHttp1Message } from "../types.js";

/** Max body bytes surfaced in an HTTP/1.1 preview. */
const HTTP1_BODY_PREVIEW_LIMIT = 256;

/** Decode a raw HTTP/1.1 request/response from wire bytes into a readable shape. */
export function decodeHttp1Message(bytes: Uint8Array): DecodedHttp1Message {
    const text = bytesToAscii(bytes);
    const headerEnd = text.indexOf("\r\n\r\n");
    if (headerEnd === -1) {
        // No complete header section — surface what we have as an unparsed start line.
        return {
            kind: "response",
            statusLine: text.slice(0, 120),
            statusCode: null,
            headers: new Map(),
            bodyPreview: "",
        };
    }
    const headerSection = text.slice(0, headerEnd);
    const bodyStart = headerEnd + 4;
    const lines = headerSection.split("\r\n");
    const startLine = lines[0] ?? "";
    const { kind, statusCode } = parseHttp1StartLine(startLine);
    const headers = parseHttp1Headers(lines.slice(1));
    const bodyPreview = previewHttp1Body(bytes, bodyStart, headers);
    return { kind, statusLine: startLine, statusCode, headers, bodyPreview };
}

/** Classify the start line as a request line or a status line and pull the code. */
function parseHttp1StartLine(line: string): { kind: "request" | "response"; statusCode: number | null } {
    const statusMatch = /^HTTP\/\d\.\d\s+(\d{3})\s/u.exec(line);
    if (statusMatch !== null) {
        const code = statusMatch[1] === undefined ? null : Number(statusMatch[1]);
        return { kind: "response", statusCode: code };
    }
    return { kind: "request", statusCode: null };
}

/** Parse header lines into a case-insensitive map (duplicates overwritten). */
function parseHttp1Headers(lines: readonly string[]): Map<string, string> {
    const headers = new Map<string, string>();
    for (const line of lines) {
        if (line.length === 0) {
            continue;
        }
        const colon = line.indexOf(":");
        if (colon === -1) {
            continue;
        }
        const name = line.slice(0, colon).trim().toLowerCase();
        const value = line.slice(colon + 1).trim();
        headers.set(name, value);
    }
    return headers;
}

/**
 * Slice the body per Content-Length / transfer-encoding and decode a short
 * UTF-8 preview. Falls back to a raw slice when neither hint is present.
 */
function previewHttp1Body(
    bytes: Uint8Array,
    bodyStart: number,
    headers: ReadonlyMap<string, string>,
): string {
    if (bodyStart >= bytes.length) {
        return "";
    }
    const transferEncoding = headers.get("transfer-encoding");
    let body = bytes.subarray(bodyStart);
    if (transferEncoding !== undefined && transferEncoding.includes("chunked")) {
        body = decodeChunkedBody(body);
    } else {
        const contentLength = headers.get("content-length");
        if (contentLength !== undefined) {
            const cl = Number(contentLength);
            if (Number.isFinite(cl) && cl >= 0) {
                body = body.subarray(0, Math.min(cl, body.length));
            }
        }
    }
    const preview = body.subarray(0, Math.min(HTTP1_BODY_PREVIEW_LIMIT, body.length));
    return new TextDecoder("utf-8", { fatal: false }).decode(preview);
}

/** Minimal chunked transfer-encoding decoder (size line + data + CRLF chunks). */
function decodeChunkedBody(bytes: Uint8Array): Uint8Array {
    const out: number[] = [];
    let pos = 0;
    for (;;) {
        let lineEnd = -1;
        for (let i = pos; i + 1 < bytes.length; i++) {
            if (bytes[i] === 0x0d && bytes[i + 1] === 0x0a) {
                lineEnd = i;
                break;
            }
        }
        if (lineEnd === -1) {
            break;
        }
        const size = Number.parseInt(bytesToAscii(bytes.subarray(pos, lineEnd)), 16);
        if (!Number.isFinite(size)) {
            break;
        }
        const dataStart = lineEnd + 2;
        if (size === 0) {
            break;
        }
        const dataEnd = dataStart + size;
        if (dataEnd > bytes.length) {
            break;
        }
        for (const byte of bytes.subarray(dataStart, dataEnd)) {
            out.push(byte);
        }
        pos = dataEnd + 2; // skip the chunk's trailing CRLF
    }
    return Uint8Array.from(out);
}

/** Lossless ASCII decode (headers are ASCII on the wire). */
function bytesToAscii(bytes: Uint8Array): string {
    let out = "";
    for (const byte of bytes) {
        out += String.fromCodePoint(byte);
    }
    return out;
}
