/**
 * @browsercore/devtools — public API surface.
 *
 * Developer tooling: packet inspector, TLS/HTTP2 visualizer, profile diff,
 * certificate inspector, benchmark CLI. Depends on the library but is NOT
 * required by it.
 */

export { createInspectorSession, decodeTlsRecord, decodeHttp2Frame } from "./inspector/inspector.js";
export { visualizeTlsHandshake, visualizeHttp2Stream, decodeHttp1Message } from "./visualizer/visualizer.js";
export { diffProfiles } from "./diff/profileDiff.js";
export { inspectCertificate } from "./cert/certInspector.js";
export { exportToJson, exportToHtml } from "./exporters.js";

export {
    DevtoolsError,
    CertParseError,
    Http2DecodeError,
    ProfileDiffError,
    TlsDecodeError,
} from "./errors.js";

export type {
    CertInfo,
    DecodedHttp1Message,
    DecodedHttp2Frame,
    DecodedTlsRecord,
    InspectionSession,
    InspectorSessionId,
    PacketDirection,
    PacketFrame,
    PacketProtocol,
    ProfileDiff,
    ProfileDiffEntry,
} from "./types.js";

export { assertNever, createId } from "./utils.js";
