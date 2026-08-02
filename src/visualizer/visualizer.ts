/**
 * Human-readable visualizers for captured protocol traffic.
 *
 * Turns an {@link InspectionSession} into a structured, ASCII-formatted trace:
 * one line per frame, with direction arrows, timestamps, and best-effort
 * decoded summaries. TLS records and HTTP/2 frames get protocol-specific
 * summaries; other protocols fall back to a generic hex preview.
 */

import { decodeHttp2Frame, decodeTlsRecord } from "../inspector/inspector.js";
import type { DecodedHttp1Message, InspectionSession, PacketFrame } from "../types.js";
import { assertNever } from "../utils.js";

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
        for (let i = dataStart; i < dataEnd; i++) {
            const byte = bytes[i];
            if (byte !== undefined) {
                out.push(byte);
            }
        }
        pos = dataEnd + 2; // skip the chunk's trailing CRLF
    }
    return Uint8Array.from(out);
}

/** Lossless ASCII decode (headers are ASCII on the wire). */
function bytesToAscii(bytes: Uint8Array): string {
    let out = "";
    for (let i = 0; i < bytes.length; i++) {
        const byte = bytes[i];
        if (byte !== undefined) {
            out += String.fromCodePoint(byte);
        }
    }
    return out;
}

/** Arrow glyph for a packet direction. */
function directionGlyph(direction: "sent" | "received"): string {
    switch (direction) {
        case "sent":
            return "→";
        case "received":
            return "←";
        default:
            return assertNever(direction);
    }
}

/** Format a millisecond timestamp as HH:MM:SS.mmm. */
function formatTime(ms: number): string {
    const d = new Date(ms);
    const hh = d.getUTCHours().toString().padStart(2, "0");
    const mm = d.getUTCMinutes().toString().padStart(2, "0");
    const ss = d.getUTCSeconds().toString().padStart(2, "0");
    const mmm = d.getUTCMilliseconds().toString().padStart(3, "0");
    return `${hh}:${mm}:${ss}.${mmm}`;
}

/** Hex preview of the first `max` bytes. */
function hexPreview(bytes: Uint8Array, max = 16): string {
    const slice = bytes.subarray(0, Math.min(max, bytes.length));
    let out = "";
    for (let i = 0; i < slice.length; i++) {
        const byte = slice[i];
        if (byte !== undefined) {
            out += byte.toString(16).padStart(2, "0");
            if (i < slice.length - 1) {
                out += " ";
            }
        }
    }
    if (bytes.length > max) {
        out += ` … (+${bytes.length - max} bytes)`;
    }
    return out;
}

/** Render a single TLS frame line. */
function renderTlsLine(frame: PacketFrame, decoded: ReturnType<typeof decodeTlsRecord>): string {
    const arrow = directionGlyph(frame.direction);
    const time = formatTime(frame.timestamp);
    const fragLen = decoded.fragments[0]?.length ?? 0;
    return `${time} ${arrow} TLS ${decoded.version} (${fragLen} byte payload)\n         ${hexPreview(frame.bytes)}`;
}

/** Render a single HTTP/2 frame line. */
function renderHttp2Line(frame: PacketFrame, decoded: ReturnType<typeof decodeHttp2Frame>): string {
    const arrow = directionGlyph(frame.direction);
    const time = formatTime(frame.timestamp);
    const typeName = http2FrameTypeName(decoded.type);
    const flagHex = `0x${decoded.flags.toString(16).padStart(2, "0")}`;
    return `${time} ${arrow} HTTP/2 ${typeName} (stream=${decoded.streamId}, flags=${flagHex}, ${decoded.payload.length} bytes)\n         ${hexPreview(frame.bytes)}`;
}

/** Render a single HTTP/1.1 message line. */
function renderHttp1Line(frame: PacketFrame, decoded: DecodedHttp1Message): string {
    const arrow = directionGlyph(frame.direction);
    const time = formatTime(frame.timestamp);
    const code = decoded.statusCode === null ? "" : ` (${decoded.statusCode})`;
    const headerCount = decoded.headers.size;
    let line = `${time} ${arrow} HTTP/1.1 ${decoded.statusLine}${code} (${headerCount} headers)`;
    if (decoded.bodyPreview.length > 0) {
        line += `\n         body: ${decoded.bodyPreview}`;
    }
    return line;
}

/** Render a generic frame line (protocol not specifically decoded). */
function renderGenericLine(frame: PacketFrame): string {
    const arrow = directionGlyph(frame.direction);
    const time = formatTime(frame.timestamp);
    return `${time} ${arrow} ${frame.protocol.toUpperCase()} (${frame.bytes.length} bytes)\n         ${hexPreview(frame.bytes)}`;
}

/** HTTP/2 frame-type names. */
const HTTP2_FRAME_TYPES: Readonly<Record<number, string>> = {
    0: "DATA",
    1: "HEADERS",
    2: "PRIORITY",
    3: "RST_STREAM",
    4: "SETTINGS",
    5: "PUSH_PROMISE",
    6: "PING",
    7: "GOAWAY",
    8: "WINDOW_UPDATE",
    9: "CONTINUATION",
};

/** Best-effort human-readable label for an HTTP/2 frame type code. */
function http2FrameTypeName(type: number): string {
    return HTTP2_FRAME_TYPES[type] ?? `0x${type.toString(16)}`;
}

/** Render one frame to a string, choosing the protocol-specific presentation. */
export function renderFrame(frame: PacketFrame): string {
    switch (frame.protocol) {
        case "tls": {
            const decoded = decodeTlsRecord(frame.bytes);
            return renderTlsLine(frame, decoded);
        }
        case "http2": {
            const decoded = decodeHttp2Frame(frame.bytes);
            return renderHttp2Line(frame, decoded);
        }
        case "http1": {
            const decoded = decodeHttp1Message(frame.bytes);
            return renderHttp1Line(frame, decoded);
        }
        case "tcp":
            return renderGenericLine(frame);
        default:
            return assertNever(frame.protocol);
    }
}

/** Section header for a trace. */
function sectionHeader(title: string, count: number): string {
    return `── ${title} (${count} frames) ──`;
}

/** Render a TLS handshake as a human-readable ASCII trace. */
export function visualizeTlsHandshake(session: InspectionSession): string {
    const frames = session.filter((f) => f.protocol === "tls");
    const lines: string[] = [
        `Session ${session.id}`,
        sectionHeader("TLS", frames.length),
    ];
    if (frames.length === 0) {
        lines.push("(no TLS frames captured)");
        return lines.join("\n");
    }
    for (const frame of frames) {
        lines.push(renderFrame(frame));
    }
    return lines.join("\n");
}

/** Render an HTTP/2 stream's frames as a human-readable ASCII trace. */
export function visualizeHttp2Stream(session: InspectionSession): string {
    const frames = session.filter((f) => f.protocol === "http2");
    const lines: string[] = [
        `Session ${session.id}`,
        sectionHeader("HTTP/2", frames.length),
    ];
    if (frames.length === 0) {
        lines.push("(no HTTP/2 frames captured)");
        return lines.join("\n");
    }
    for (const frame of frames) {
        lines.push(renderFrame(frame));
    }
    return lines.join("\n");
}
