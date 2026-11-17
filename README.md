# @browsercore/devtools


[![npm version](https://img.shields.io/npm/v/@browsercore/devtools)](https://www.npmjs.com/package/@browsercore/devtools)
[![coverage](https://img.shields.io/endpoint?url=https://jverneuer.github.io/browsercore-devtools/badge.json)](https://jverneuer.github.io/browsercore-devtools/COVERAGE.md)
[![CI](https://img.shields.io/github/actions/workflow/status/jverneuer/browsercore-devtools/ci.yml?label=ci)](https://github.com/jverneuer/browsercore-devtools/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/@browsercore/devtools.svg)](LICENSE)

Developer tooling for the browsercore stack: packet inspector, TLS/HTTP visualizers,
profile diff, certificate inspector, and the `network-devtools` CLI. Depends on the
library but is NOT required by it — every tool here consumes the public API of the
lower-level packages, and nothing here is imported by them.

## Install

```bash
npm install @browsercore/devtools
```

## Quick usage

```ts
import {
    createInspectorSession,
    visualizeTlsHandshake,
    diffProfiles,
    inspectCertificate,
} from "@browsercore/devtools";

// Capture frames into a live session, then render a TLS handshake trace:
const session = createInspectorSession();
session.addFrame({ direction: "sent", protocol: "tls", bytes: clientHello, decoded: null });
console.log(visualizeTlsHandshake(session));

// Diff two browser profiles field-by-field:
const diff = diffProfiles("chrome-140" as never, "firefox-135" as never);
console.log(diff.differences);

// Parse a PEM/DER X.509 certificate:
const info = inspectCertificate(pemBytes);
console.log(info.subject, info.fingerprintSha256);
```

## Public API

| Export | Kind | Purpose |
| --- | --- | --- |
| `createInspectorSession()` | function | Start an empty inspection session |
| `decodeTlsRecord()` | function | Decode a TLS record from raw bytes |
| `decodeHttp2Frame()` | function | Decode an HTTP/2 frame header + payload |
| `decodeHttp1Message()` | function | Parse an HTTP/1.1 request/response |
| `visualizeTlsHandshake()` | function | Render a captured TLS handshake as an ASCII trace |
| `visualizeHttp2Stream()` | function | Render captured HTTP/2 frames as an ASCII trace |
| `diffProfiles()` | function | Compare two browser profiles field-by-field |
| `inspectCertificate()` | function | Parse a PEM/DER X.509 certificate into a summary |
| `exportToJson()` | function | Stable, human-readable JSON (2-space indent) |
| `exportToHtml()` | function | Render a value as a self-contained HTML document |
| `assertNever()` | function | Exhaustiveness check for `switch` over unions |
| `createId()` | function | Unique, branded-id generator |
| `InspectionSession` | interface | Live session: append frames, filter, visualize |
| `PacketFrame` | interface | A single captured frame (direction, protocol, bytes) |
| `PacketDirection` | union | `"sent" \| "received"` |
| `PacketProtocol` | union | `"tls" \| "http2" \| "http1" \| "tcp"` |
| `DecodedTlsRecord` | interface | Decoded TLS record (content type, version, fragments) |
| `DecodedHttp2Frame` | interface | Decoded HTTP/2 frame (type, flags, streamId, payload) |
| `DecodedHttp1Message` | interface | Parsed HTTP/1.1 request/response |
| `CertInfo` | interface | Parsed certificate summary (subject, issuer, SAN, fingerprint) |
| `ProfileDiff` / `ProfileDiffEntry` | interface | Result of diffing two profiles |
| `InspectorSessionId` | branded type | Branded session identifier |
| `DevtoolsError` | class | Base typed error (carries `kind` + `cause`) |
| `CertParseError` | class | Certificate could not be parsed |
| `TlsDecodeError` | class | TLS record could not be decoded |
| `Http2DecodeError` | class | HTTP/2 frame could not be decoded |
| `ProfileDiffError` | class | Profile diff could not be computed |


## Stack versions

Devtools tracks the **platform-v2 stack**: a canonical `Clock` and the optional
`Platform` / engine-injection surface defined in
[`@browsercore/contracts`](https://github.com/jverneuer/browsercore-contracts)
and assembled by [`browsersmith`](https://github.com/jverneuer/browsersmith),
the composition root. The inspector still consumes the wire-facing parser
exports (`parseRecordHeader` from `@browsercore/tls`, `parseFrameHeader` from
`@browsercore/http2`) — platform-v2 was a type/wiring/injection change only, so
decoding output is unchanged.

| Package | Version |
| --- | --- |
| `@browsercore/tls` | ^0.4.17 |
| `@browsercore/http2` | 0.2.14 |
| `@browsercore/http1` | 0.2.6 |
| `@browsercore/profiles` | 0.2.6 |
| `@browsercore/cookies` | 0.2.3 |
| `@browsercore/crypto` | 0.2.7 |
| `@browsercore/transport` | 0.2.10 |
| `@browsercore/fetch` | 0.2.25 |

## Contributing

Contributions are welcome — bug reports, reproductions, docs and code alike. Start with [CONTRIBUTING.md](CONTRIBUTING.md); the full guide lives in the [browsersmith repo](https://github.com/jverneuer/browsersmith/blob/main/CONTRIBUTING.md). First timer? Check the [`good first issue`](https://github.com/jverneuer/browsercore-devtools/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) label. Security issues: [SECURITY.md](SECURITY.md), never a public issue.

## License

MIT
