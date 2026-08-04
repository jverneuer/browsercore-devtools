import { describe, expect, it } from "vitest";
import { renderFrame, visualizeTlsHandshake, visualizeHttp2Stream } from "../src/visualizer/visualizer.js";
import { createInspectorSession } from "../src/inspector/inspector.js";
import { TlsDecodeError } from "../src/errors.js";
import type { PacketFrame } from "../src/types.js";

function frame(
    protocol: PacketFrame["protocol"],
    bytes: Uint8Array,
    direction: "sent" | "received" = "sent",
    timestamp = 0,
): PacketFrame {
    return { timestamp, direction, protocol, bytes, decoded: null };
}

describe("renderFrame — timestamp & hex-preview formatting", () => {
    it("formats the UTC timestamp as HH:MM:SS.mmm", () => {
        // Epoch (UTC) -> 00:00:00.000.
        const out = renderFrame(frame("tcp", new Uint8Array([0x01]), "sent", 0));
        expect(out).toContain("00:00:00.000");
    });

    it("renders a full 16-byte hex preview without an overflow indicator", () => {
        const bytes = new Uint8Array(16); // all zeros
        const out = renderFrame(frame("tcp", bytes));
        // 16 space-separated "00" pairs, no ellipsis overflow marker.
        expect(out).toContain("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
        // The overflow marker is `… (+N bytes)`; absent when bytes fit the cap.
        // (The generic line still reports the total length as "(16 bytes)".)
        expect(out).not.toContain("… (+");
    });

    it("renders a 15-byte hex preview (under the cap) with no trailing separator", () => {
        const bytes = new Uint8Array(15).fill(0xab);
        const out = renderFrame(frame("tcp", bytes));
        // 15 pairs, last pair has no trailing space.
        expect(out.trimEnd()).toMatch(/ab$/);
        expect(out).not.toContain("… (+");
    });

    it("reports the exact overflow byte count past the 16-byte cap", () => {
        const bytes = new Uint8Array(20); // 4 bytes over the 16-byte preview cap
        const out = renderFrame(frame("tcp", bytes));
        expect(out).toContain("… (+4 bytes)");
    });

    it("formats the TLS legacy version as 0xMMmm (label)", () => {
        // ContentType=22 (handshake), version 0x0303, length 0.
        const out = renderFrame(frame("tls", new Uint8Array([0x16, 0x03, 0x03, 0x00, 0x00])));
        expect(out).toContain("0x0303 (handshake)");
    });
});

describe("renderFrame — direction & payload summaries", () => {
    it("uses the sent arrow (→) for sent frames", () => {
        expect(renderFrame(frame("tcp", new Uint8Array([0x01]), "sent"))).toContain("→");
    });

    it("uses the received arrow (←) for received frames", () => {
        expect(renderFrame(frame("tcp", new Uint8Array([0x01]), "received"))).toContain("←");
    });

    it("summarizes an HTTP/2 frame with stream id, flags, and payload length", () => {
        // 9-byte header: length=2 (3 bytes), type=0 (DATA), flags=0x04, streamId=5,
        // followed by 2 payload bytes.
        const bytes = new Uint8Array([0x00, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x05, 0xaa, 0xbb]);
        const out = renderFrame(frame("http2", bytes));
        expect(out).toContain("DATA");
        expect(out).toContain("stream=5");
        expect(out).toContain("flags=0x04");
        expect(out).toContain("2 bytes");
    });

    it("upper-cases the protocol tag for generic (TCP) frames", () => {
        const out = renderFrame(frame("tcp", new Uint8Array([0x01, 0x02])));
        expect(out).toContain("TCP");
        expect(out).toContain("2 bytes");
    });
});

describe("visualize* — trace structure", () => {
    it("renders a section header with the frame count for a TLS trace", () => {
        const session = createInspectorSession();
        session.addFrame(frame("tls", new Uint8Array([0x16, 0x03, 0x03, 0x00, 0x00])));
        session.addFrame(frame("tls", new Uint8Array([0x16, 0x03, 0x03, 0x00, 0x00])));
        const out = visualizeTlsHandshake(session);
        expect(out).toContain("── TLS (2 frames) ──");
        expect(out).toContain(`Session ${session.id}`);
    });

    it("renders frames in insertion order within an HTTP/2 trace", () => {
        const session = createInspectorSession();
        // streamId 1 then streamId 2 — the trace must preserve capture order.
        session.addFrame(
            frame("http2", new Uint8Array([0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x01])),
        );
        session.addFrame(
            frame("http2", new Uint8Array([0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02])),
        );
        const out = visualizeHttp2Stream(session);
        const firstStream = out.indexOf("stream=1");
        const secondStream = out.indexOf("stream=2");
        expect(firstStream).toBeGreaterThan(-1);
        expect(secondStream).toBeGreaterThan(firstStream);
    });

    it("propagates TlsDecodeError when a captured TLS frame cannot be decoded", () => {
        // visualize* does not swallow decode errors — a malformed frame in a session
        // surfaces the failure to the caller. This documents the contract: callers
        // that want fault-tolerant visualization must filter/sanitize frames first.
        const session = createInspectorSession();
        session.addFrame(frame("tls", new Uint8Array([0x16, 0x03]))); // truncated record header
        expect(() => visualizeTlsHandshake(session)).toThrow(TlsDecodeError);
    });

    it("ignores non-matching protocols when building a TLS trace", () => {
        const session = createInspectorSession();
        session.addFrame(frame("http2", new Uint8Array(9)));
        session.addFrame(frame("tcp", new Uint8Array([0x01])));
        const out = visualizeTlsHandshake(session);
        expect(out).toContain("(no TLS frames captured)");
        expect(out).toContain("── TLS (0 frames) ──");
    });
});

describe("renderFrame — exhaustiveness guards (assertNever)", () => {
    it("throws via assertNever for an unhandled protocol", () => {
        // The switch in renderFrame is exhaustive over PacketProtocol; a value
        // outside the union must fall through to the default → assertNever.
        const bad = { timestamp: 0, direction: "sent", protocol: "quic", bytes: new Uint8Array(), decoded: null };
        expect(() => renderFrame(bad as PacketFrame)).toThrow(/Unexpected value/);
    });

    it("throws via assertNever for an unhandled direction", () => {
        // directionGlyph is exhaustive over PacketDirection; an invalid direction
        // (reached via the generic TCP renderer) must hit its default → assertNever.
        const bad = { timestamp: 0, direction: "sideways", protocol: "tcp", bytes: new Uint8Array([0x01]), decoded: null };
        expect(() => renderFrame(bad as PacketFrame)).toThrow(/Unexpected value/);
    });
});
