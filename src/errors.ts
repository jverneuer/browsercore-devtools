/**
 * Typed errors for @network/devtools.
 *
 * Errors are part of the API — every failure mode is an explicit type so callers
 * can match on `kind` instead of parsing messages.
 */

/** Base class for every devtools error. */
export class DevtoolsError extends Error {
    public readonly kind: string;
    public override readonly cause: Error | undefined;

    constructor(kind: string, message: string, options?: { cause?: Error }) {
        super(message, options);
        this.name = new.target.name;
        this.kind = kind;
        this.cause = options?.cause;
    }
}

/** A certificate could not be parsed from the supplied bytes. */
export class CertParseError extends DevtoolsError {
    public override readonly kind = "CertParseError" as const;

    constructor(message: string, options?: { cause?: Error }) {
        super("CertParseError", message, options);
    }
}

/** A TLS record could not be decoded. */
export class TlsDecodeError extends DevtoolsError {
    public override readonly kind = "TlsDecodeError" as const;

    constructor(message: string, options?: { cause?: Error }) {
        super("TlsDecodeError", message, options);
    }
}

/** An HTTP/2 frame could not be decoded. */
export class Http2DecodeError extends DevtoolsError {
    public override readonly kind = "Http2DecodeError" as const;

    constructor(message: string, options?: { cause?: Error }) {
        super("Http2DecodeError", message, options);
    }
}

/** A profile diff could not be computed (unknown profile id, etc.). */
export class ProfileDiffError extends DevtoolsError {
    public override readonly kind = "ProfileDiffError" as const;

    constructor(message: string, options?: { cause?: Error }) {
        super("ProfileDiffError", message, options);
    }
}
