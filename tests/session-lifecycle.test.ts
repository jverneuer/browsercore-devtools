import { describe, expect, it } from "vitest";
import { createInspectorSession } from "../src/inspector/inspector.js";

describe("inspector session — lifecycle and isolation", () => {
    it("assigns distinct ids to separate sessions", () => {
        const a = createInspectorSession();
        const b = createInspectorSession();
        expect(a.id).not.toBe(b.id);
    });

    it("starts empty and reflects appended frames in the readonly view", () => {
        const session = createInspectorSession();
        expect(session.frames.length).toBe(0);
        session.addFrame({ direction: "sent", protocol: "tcp", bytes: new Uint8Array([1]), decoded: null });
        expect(session.frames.length).toBe(1);
    });

    it("stores the exact bytes reference (no defensive copy)", () => {
        const session = createInspectorSession();
        const bytes = new Uint8Array([0xde, 0xad]);
        session.addFrame({ direction: "sent", protocol: "tcp", bytes, decoded: null });
        expect(session.frames[0]!.bytes).toBe(bytes);
    });

    it("preserves a non-null decoded payload verbatim", () => {
        const session = createInspectorSession();
        const decoded = { summary: "ok", fields: [1, 2, 3] };
        session.addFrame({ direction: "received", protocol: "http2", bytes: new Uint8Array(), decoded });
        expect(session.frames[0]!.decoded).toBe(decoded);
    });

    it("preserves an explicit 0 timestamp rather than treating it as omitted", () => {
        const session = createInspectorSession();
        session.addFrame({ direction: "sent", protocol: "tcp", bytes: new Uint8Array(), decoded: null, timestamp: 0 });
        expect(session.frames[0]!.timestamp).toBe(0);
    });

    it("filter returns a fresh array (mutating the result does not affect the session)", () => {
        const session = createInspectorSession();
        session.addFrame({ direction: "sent", protocol: "tls", bytes: new Uint8Array(), decoded: null });
        session.addFrame({ direction: "received", protocol: "tls", bytes: new Uint8Array(), decoded: null });
        const filtered = session.filter((f) => f.protocol === "tls");
        expect(filtered).toHaveLength(2);
        // Mutate the returned array; the session's own frame list is unaffected.
        filtered.length = 0;
        expect(session.frames.length).toBe(2);
    });

    it("filter predicate that matches nothing returns an empty array", () => {
        const session = createInspectorSession();
        session.addFrame({ direction: "sent", protocol: "tls", bytes: new Uint8Array(), decoded: null });
        expect(session.filter((f) => f.protocol === "quic")).toEqual([]);
    });

    it("filter can match on direction and timestamp fields", () => {
        const session = createInspectorSession();
        session.addFrame({ direction: "sent", protocol: "tls", bytes: new Uint8Array(), decoded: null, timestamp: 100 });
        session.addFrame({ direction: "received", protocol: "tls", bytes: new Uint8Array(), decoded: null, timestamp: 200 });
        session.addFrame({ direction: "sent", protocol: "tls", bytes: new Uint8Array(), decoded: null, timestamp: 300 });
        const sentLate = session.filter((f) => f.direction === "sent" && f.timestamp >= 200);
        expect(sentLate).toHaveLength(1);
        expect(sentLate[0]!.timestamp).toBe(300);
    });
});

describe("inspector session — concurrency / ordering", () => {
    it("preserves insertion order across a large batch of mixed-protocol frames", () => {
        const session = createInspectorSession();
        const protocols = ["tls", "http2", "http1", "tcp"] as const;
        for (let i = 0; i < 1000; i++) {
            const protocol = protocols[i % protocols.length]!;
            session.addFrame({
                direction: i % 2 === 0 ? "sent" : "received",
                protocol,
                bytes: new Uint8Array([i & 0xff]),
                decoded: null,
                timestamp: i,
            });
        }
        expect(session.frames.length).toBe(1000);
        // Insertion order is preserved.
        expect(session.frames[0]!.timestamp).toBe(0);
        expect(session.frames[999]!.timestamp).toBe(999);
        // Filtering does not reorder.
        const h2 = session.filter((f) => f.protocol === "http2");
        expect(h2.length).toBe(250);
        expect(h2[0]!.timestamp).toBe(1);
        expect(h2[h2.length - 1]!.timestamp).toBe(997);
    });

    it("two sessions do not share frame state", () => {
        const a = createInspectorSession();
        const b = createInspectorSession();
        a.addFrame({ direction: "sent", protocol: "tcp", bytes: new Uint8Array([1]), decoded: null });
        expect(a.frames.length).toBe(1);
        expect(b.frames.length).toBe(0);
        b.addFrame({ direction: "sent", protocol: "tcp", bytes: new Uint8Array([2]), decoded: null });
        expect(a.frames[0]!.bytes[0]).toBe(1);
        expect(b.frames[0]!.bytes[0]).toBe(2);
    });
});
