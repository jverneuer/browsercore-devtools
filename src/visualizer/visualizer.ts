/**
 * Human-readable visualizers for captured protocol traffic.
 *
 * Turns an {@link InspectionSession} into a structured, ASCII-formatted trace:
 * one line per frame, with direction arrows, timestamps, and best-effort
 * decoded summaries. TLS records and HTTP/2 frames get protocol-specific
 * summaries; other protocols fall back to a generic hex preview.
 */

import { decodeHttp2Frame, decodeTlsRecord } from "../inspector/inspector.js";
import type { DecodedHttp1Message, DecodedHttp2Frame, DecodedTlsRecord, InspectionSession, PacketFrame } from "../types.js";
import { assertNever } from "../utils.js";
import { decodeHttp1Message } from "./http1.js";

// Re-export so the public API surface (and tests) keeps a single import path.
export { decodeHttp1Message };

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
function renderTlsLine(frame: PacketFrame, decoded: DecodedTlsRecord): string {
    const arrow = directionGlyph(frame.direction);
    const time = formatTime(frame.timestamp);
    const fragLen = decoded.fragments[0]?.length ?? 0;
    return `${time} ${arrow} TLS ${decoded.version} (${fragLen} byte payload)\n         ${hexPreview(frame.bytes)}`;
}

/** Render a single HTTP/2 frame line. */
function renderHttp2Line(frame: PacketFrame, decoded: DecodedHttp2Frame): string {
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
