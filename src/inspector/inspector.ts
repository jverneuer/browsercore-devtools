/**
 * Inspection session — capture, decode, and filter protocol frames.
 *
 * `createInspectorSession` owns the in-memory frame log; the decoders lean on
 * the real wire-format parsers from @network/tls and @network/http2 so the
 * inspector benefits from their validation without duplicating parsing logic.
 */

import { parseRecordHeader, RECORD_HEADER_SIZE } from "@network/tls";
import { FRAME_HEADER_LENGTH, parseFrameHeader } from "@network/http2";
import { Http2DecodeError } from "../errors.js";
import { TlsDecodeError } from "../errors.js";
import type {
    DecodedHttp2Frame,
    DecodedTlsRecord,
    InspectionSession,
    InspectorSessionId,
    PacketFrame,
} from "../types.js";
import { createId } from "../utils.js";

/** TLS record content-type names, for the decoded `version` field. */
const TLS_CONTENT_TYPES: Readonly<Record<number, string>> = {
    20: "change_cipher_spec",
    21: "alert",
    22: "handshake",
    23: "application_data",
};

/** HTTP/2 frame-type names, for the decoded `type` field. */
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

/**
 * Create an empty inspection session. Frames are appended via
 * {@link InspectionSession.addFrame}.
 */
export function createInspectorSession(): InspectionSession {
    const frames: PacketFrame[] = [];
    const id = createId("insp") as InspectorSessionId;
    return {
        id,
        frames: frames as ReadonlyArray<PacketFrame>,
        addFrame(frame) {
            frames.push({
                timestamp: frame.timestamp ?? Date.now(),
                direction: frame.direction,
                protocol: frame.protocol,
                bytes: frame.bytes,
                decoded: frame.decoded,
            });
        },
        filter(predicate) {
            return frames.filter(predicate);
        },
    };
}

/** Format a TLS 16-bit legacy version as "major.minor". */
function formatTlsVersion(version: number): string {
    const major = (version >> 8) & 0xff;
    const minor = version & 0xff;
    return `0x${major.toString(16).padStart(2, "0")}${minor.toString(16).padStart(2, "0")}`;
}

/** Decode a TLS record from raw bytes. Throws {@link TlsDecodeError} on malformed input. */
export function decodeTlsRecord(bytes: Uint8Array): DecodedTlsRecord {
    try {
        const header = parseRecordHeader(bytes);
        const fragmentStart = RECORD_HEADER_SIZE;
        const fragmentEnd = Math.min(fragmentStart + header.length, bytes.length);
        const fragment = bytes.subarray(fragmentStart, fragmentEnd);
        const contentTypeLabel = tlsContentTypeLabel(header.type);
        return {
            contentType: header.type,
            version: `${formatTlsVersion(header.version)} (${contentTypeLabel})`,
            fragments: [fragment],
        };
    } catch (err) {
        const cause = err instanceof Error ? err : undefined;
        const message = `failed to decode TLS record: ${err instanceof Error ? err.message : String(err)}`;
        throw new TlsDecodeError(message, cause === undefined ? undefined : { cause });
    }
}

/**
 * Decode an HTTP/2 frame header + payload from raw bytes. Throws
 * {@link Http2DecodeError} on malformed input.
 */
export function decodeHttp2Frame(bytes: Uint8Array): DecodedHttp2Frame {
    try {
        const header = parseFrameHeader(bytes);
        const payloadStart = FRAME_HEADER_LENGTH;
        const payloadEnd = Math.min(payloadStart + header.length, bytes.length);
        const payload = bytes.subarray(payloadStart, payloadEnd);
        // Map the branded Http2StreamId back to a plain number for the summary shape.
        const streamId = header.streamId as number;
        return {
            type: header.type,
            flags: header.flags,
            streamId,
            payload,
        };
    } catch (err) {
        const cause = err instanceof Error ? err : undefined;
        const message = `failed to decode HTTP/2 frame: ${err instanceof Error ? err.message : String(err)}`;
        throw new Http2DecodeError(message, cause === undefined ? undefined : { cause });
    }
}

/** Best-effort human-readable label for an HTTP/2 frame type code. */
export function http2FrameTypeName(type: number): string {
    return HTTP2_FRAME_TYPES[type] ?? `unknown(0x${type.toString(16)})`;
}

/** Best-effort human-readable label for a TLS record content type. */
export function tlsContentTypeLabel(type: number): string {
    return TLS_CONTENT_TYPES[type] ?? `unknown(0x${type.toString(16)})`;
}
