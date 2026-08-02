import { describe, expect, it } from "vitest";
import { createInspectorSession, decodeTlsRecord, decodeHttp2Frame, http2FrameTypeName, tlsContentTypeLabel } from "../src/inspector/inspector.js";
import { TlsDecodeError, Http2DecodeError } from "../src/errors.js";

describe("createInspectorSession", () => {
    it("assigns a branded id and starts empty", () => {
        const session = createInspectorSession();
        expect(session.frames).toEqual([]);
        expect(typeof session.id).toBe("string");
        expect(session.id.startsWith("insp_")).toBe(true);
    });

    it("addFrame fills in a timestamp when omitted", () => {
        const session = createInspectorSession();
        session.addFrame({ direction: "sent", protocol: "tcp", bytes: new Uint8Array(), decoded: null });
        const frame = session.frames[0]!;
        expect(typeof frame.timestamp).toBe("number");
    });

    it("addFrame preserves an explicit timestamp", () => {
        const session = createInspectorSession();
        session.addFrame({ direction: "sent", protocol: "tcp", bytes: new Uint8Array(), decoded: null, timestamp: 12345 });
        expect(session.frames[0]!.timestamp).toBe(12345);
    });

    it("filter returns only matching frames", () => {
        const session = createInspectorSession();
        session.addFrame({ direction: "sent", protocol: "tls", bytes: new Uint8Array(), decoded: null });
        session.addFrame({ direction: "received", protocol: "http2", bytes: new Uint8Array(), decoded: null });
        const tls = session.filter((f) => f.protocol === "tls");
        expect(tls.length).toBe(1);
        expect(tls[0]!.protocol).toBe("tls");
    });
});

describe("decodeTlsRecord", () => {
    it("decodes a handshake record header", () => {
        const fragment = new Uint8Array([0x01, 0x00, 0x00, 0x20]);
        const record = new Uint8Array([0x16, 0x03, 0x03, 0x00, fragment.length, ...fragment]);
        const decoded = decodeTlsRecord(record);
        expect(decoded.contentType).toBe(22);
        expect(decoded.version).toContain("handshake");
        expect(decoded.fragments.length).toBe(1);
        expect(decoded.fragments[0]!.length).toBe(fragment.length);
    });

    it("decodes an application_data record", () => {
        const record = new Uint8Array([0x17, 0x03, 0x03, 0x00, 0x01, 0xaa]);
        const decoded = decodeTlsRecord(record);
        expect(decoded.contentType).toBe(23);
        expect(decoded.version).toContain("application_data");
    });

    it("throws TlsDecodeError on a truncated record header", () => {
        // Fewer than 5 bytes fails the underlying parser.
        const record = new Uint8Array([0x16, 0x03, 0x03]);
        expect(() => decodeTlsRecord(record)).toThrow(TlsDecodeError);
    });

    it("wraps the underlying error message on decode failure", () => {
        const record = new Uint8Array([0x16, 0x03, 0x03]);
        try {
            decodeTlsRecord(record);
        } catch (err) {
            expect(err).toBeInstanceOf(TlsDecodeError);
            expect((err as TlsDecodeError).message).toContain("failed to decode TLS record");
            return;
        }
        throw new Error("expected to throw");
    });
});

describe("decodeHttp2Frame", () => {
    it("decodes a SETTINGS frame header", () => {
        const frame = new Uint8Array([0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]);
        const decoded = decodeHttp2Frame(frame);
        expect(decoded.type).toBe(0x04);
        expect(decoded.flags).toBe(0);
        expect(decoded.streamId).toBe(0);
        expect(decoded.payload.length).toBe(0);
    });

    it("decodes a DATA frame with a payload", () => {
        // length=3, type=0 (DATA), flags=0, streamId=1, then 3 payload bytes.
        const frame = new Uint8Array([0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xaa, 0xbb, 0xcc]);
        const decoded = decodeHttp2Frame(frame);
        expect(decoded.type).toBe(0x00);
        expect(decoded.streamId).toBe(1);
        expect(decoded.payload.length).toBe(3);
        expect(decoded.payload).toEqual(new Uint8Array([0xaa, 0xbb, 0xcc]));
    });

    it("throws Http2DecodeError on a truncated frame header", () => {
        // Fewer than 9 bytes fails the underlying parser.
        const frame = new Uint8Array([0x00, 0x00, 0x00, 0x04, 0x00]);
        expect(() => decodeHttp2Frame(frame)).toThrow(Http2DecodeError);
    });

    it("wraps the underlying error message on decode failure", () => {
        const frame = new Uint8Array([0x00, 0x00, 0x00, 0x04, 0x00]);
        try {
            decodeHttp2Frame(frame);
        } catch (err) {
            expect(err).toBeInstanceOf(Http2DecodeError);
            expect((err as Http2DecodeError).message).toContain("failed to decode HTTP/2 frame");
            return;
        }
        throw new Error("expected to throw");
    });
});

describe("label helpers", () => {
    it("http2FrameTypeName resolves known types", () => {
        expect(http2FrameTypeName(0)).toBe("DATA");
        expect(http2FrameTypeName(4)).toBe("SETTINGS");
    });

    it("http2FrameTypeName formats unknown types", () => {
        expect(http2FrameTypeName(0xff)).toBe("unknown(0xff)");
    });

    it("tlsContentTypeLabel resolves known types", () => {
        expect(tlsContentTypeLabel(22)).toBe("handshake");
        expect(tlsContentTypeLabel(23)).toBe("application_data");
    });

    it("tlsContentTypeLabel formats unknown types", () => {
        expect(tlsContentTypeLabel(0xfe)).toBe("unknown(0xfe)");
    });
});
