import { describe, expect, it } from "vitest";
import { createInspectorSession } from "../src/index.js";

describe("createInspectorSession", () => {
    it("returns a session with an empty frames array", () => {
        const session = createInspectorSession();
        expect(session.frames).toEqual([]);
        expect(typeof session.id).toBe("string");
    });

    it("addFrame appends a frame with an auto timestamp", () => {
        const session = createInspectorSession();
        session.addFrame({
            direction: "sent",
            protocol: "tls",
            bytes: new Uint8Array([0x16, 0x03, 0x01]),
            decoded: null,
        });
        expect(session.frames.length).toBe(1);
        const frame = session.frames[0]!;
        expect(frame.direction).toBe("sent");
        expect(frame.protocol).toBe("tls");
        expect(frame.bytes).toEqual(new Uint8Array([0x16, 0x03, 0x01]));
        expect(typeof frame.timestamp).toBe("number");
    });

    it("filter returns matching frames", () => {
        const session = createInspectorSession();
        session.addFrame({ direction: "sent", protocol: "tls", bytes: new Uint8Array(), decoded: null });
        session.addFrame({ direction: "received", protocol: "http2", bytes: new Uint8Array(), decoded: null });
        const tls = session.filter((f) => f.protocol === "tls");
        expect(tls.length).toBe(1);
        expect(tls[0]!.protocol).toBe("tls");
    });
});
