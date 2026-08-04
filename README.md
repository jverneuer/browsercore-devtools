# @browsercore/devtools


[![npm version](https://img.shields.io/npm/v/@browsercore/devtools)](https://www.npmjs.com/package/@browsercore/devtools)
[![coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/jverneuer/browsercore-devtools/main/coverage/badge.json)](https://github.com/jverneuer/browsercore-devtools/blob/main/COVERAGE.md)
[![lint](https://img.shields.io/github/actions/workflow/status/jverneuer/browsercore-devtools/ci.yml?label=lint)](https://github.com/jverneuer/browsercore-devtools/actions/workflows/ci.yml)

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

## CLI

The `network-devtools` binary exposes the same tooling from a terminal:

```bash
network-devtools tls capture.bin         # visualize a TLS handshake
network-devtools http2 capture.bin       # visualize an HTTP/2 session
network-devtools diff chrome-140 firefox-128  # diff two profiles
network-devtools cert cert.pem            # inspect an X.509 certificate
network-devtools bench tls --iterations 100   # benchmark TLS fingerprinting
network-devtools bench http2 --iterations 100  # benchmark HTTP/2 comparison
```

`bench` runs protocol-parsing micro-benchmarks against the golden browser
captures in `@browsercore/testing` and reports avg/p50/p95/p99 latency.

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

## License

MIT
