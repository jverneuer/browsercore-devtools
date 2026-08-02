/**
 * Domain types for @browsercore/devtools.
 *
 * Developer tooling: packet inspector, TLS handshake visualizer, HTTP/2 frame
 * viewer, profile diff, certificate inspector, benchmark CLI. Depends on the
 * library but is NOT required by it.
 */

import type { ProfileId } from "@browsercore/profiles";

/** Branded inspector session identifier. */
export type InspectorSessionId = string & { __brand: "InspectorSessionId" };

/** Direction a frame flowed. */
export type PacketDirection = "sent" | "received";

/** Which protocol layer a frame belongs to. */
export type PacketProtocol = "tls" | "http2" | "http1" | "tcp";

/** A single captured packet/frame in an inspection session. */
export interface PacketFrame {
    readonly timestamp: number;
    readonly direction: PacketDirection;
    readonly protocol: PacketProtocol;
    readonly bytes: Uint8Array;
    /** Best-effort decoded representation (record-type-specific shape). */
    readonly decoded: unknown;
}

/** A live inspection session — append frames, filter, visualize. */
export interface InspectionSession {
    readonly id: InspectorSessionId;
    readonly frames: ReadonlyArray<PacketFrame>;
    addFrame(frame: Omit<PacketFrame, "timestamp"> & { timestamp?: number }): void;
    filter(predicate: (frame: PacketFrame) => boolean): ReadonlyArray<PacketFrame>;
}

/** A single field-level difference between two profiles. */
export interface ProfileDiffEntry {
    readonly path: string;
    readonly a: unknown;
    readonly b: unknown;
}

/** Result of diffing two profiles. */
export interface ProfileDiff {
    readonly profileA: ProfileId;
    readonly profileB: ProfileId;
    readonly differences: ReadonlyArray<ProfileDiffEntry>;
}

/** Decoded TLS record — content type, formatted "major.minor (label)" version, and the raw fragment(s). */
export interface DecodedTlsRecord {
    readonly contentType: number;
    readonly version: string;
    readonly fragments: ReadonlyArray<Uint8Array>;
}

/** Decoded HTTP/2 frame — 9-octet header fields plus the raw payload bytes. */
export interface DecodedHttp2Frame {
    readonly type: number;
    readonly flags: number;
    readonly streamId: number;
    readonly payload: Uint8Array;
}

/** Decoded HTTP/1.1 message — a parsed request or response. */
export interface DecodedHttp1Message {
    /** Whether this is a request line or a status line. */
    readonly kind: "request" | "response";
    /** The raw start line (request line or status line). */
    readonly statusLine: string;
    /** Response status code — `null` for requests. */
    readonly statusCode: number | null;
    /** Parsed headers (lowercased names). */
    readonly headers: ReadonlyMap<string, string>;
    /** Best-effort decoded body preview (may be empty). */
    readonly bodyPreview: string;
}

/** Parsed X.509 certificate summary. */
export interface CertInfo {
    readonly subject: string;
    readonly issuer: string;
    readonly notBefore: Date;
    readonly notAfter: Date;
    readonly san: ReadonlyArray<string>;
    readonly fingerprintSha256: string;
}
