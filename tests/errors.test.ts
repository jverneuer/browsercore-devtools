import { describe, expect, it } from "vitest";
import { DevtoolsError, CertParseError, TlsDecodeError, Http2DecodeError, ProfileDiffError } from "../src/errors.js";

describe("error types", () => {
    it("DevtoolsError carries kind, name, and optional cause", () => {
        const cause = new Error("root cause");
        const err = new DevtoolsError("Custom", "something broke", { cause });
        expect(err).toBeInstanceOf(Error);
        expect(err).toBeInstanceOf(DevtoolsError);
        expect(err.kind).toBe("Custom");
        expect(err.name).toBe("DevtoolsError");
        expect(err.message).toBe("something broke");
        expect(err.cause).toBe(cause);
    });

    it("CertParseError has the right kind and name", () => {
        const err = new CertParseError("bad cert");
        expect(err).toBeInstanceOf(DevtoolsError);
        expect(err.kind).toBe("CertParseError");
        expect(err.name).toBe("CertParseError");
        expect(err.message).toBe("bad cert");
        expect(err.cause).toBeUndefined();
    });

    it("CertParseError accepts a cause", () => {
        const cause = new Error("underlying");
        const err = new CertParseError("bad cert", { cause });
        expect(err.cause).toBe(cause);
    });

    it("TlsDecodeError has the right kind and name", () => {
        const err = new TlsDecodeError("no");
        expect(err.kind).toBe("TlsDecodeError");
        expect(err.name).toBe("TlsDecodeError");
    });

    it("Http2DecodeError has the right kind and name", () => {
        const err = new Http2DecodeError("no");
        expect(err.kind).toBe("Http2DecodeError");
        expect(err.name).toBe("Http2DecodeError");
    });

    it("ProfileDiffError has the right kind and name", () => {
        const err = new ProfileDiffError("no");
        expect(err.kind).toBe("ProfileDiffError");
        expect(err.name).toBe("ProfileDiffError");
    });

    it("each error is distinguishable by kind", () => {
        const kinds = new Set(
            [new CertParseError(""), new TlsDecodeError(""), new Http2DecodeError(""), new ProfileDiffError("")].map(
                (e) => e.kind,
            ),
        );
        expect(kinds.size).toBe(4);
    });
});
