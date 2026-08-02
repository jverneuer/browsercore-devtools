# @network/devtools — Implementation Plan

Developer tooling for protocol observability. Implement in this order; each step
is independently useful.

## Step 1 — Packet capture/inspection data model (DONE)

`createInspectorSession`, `InspectionSession`, `PacketFrame`, and frame
filtering are implemented and tested. This is the foundation every visualizer
builds on.

## Step 2 — TLS record decoder/visualizer

Implement `decodeTlsRecord` (content type, version, handshake message type) and
`visualizeTlsHandshake` (ASCII trace: ClientHello → ServerHello → … → Finished).

## Step 3 — HTTP/2 frame decoder/visualizer

Implement `decodeHttp2Frame` (9-octet header + typed payload per frame type)
and `visualizeHttp2Stream` (ASCII trace of SETTINGS/HEADERS/DATA/WINDOW_UPDATE).

## Step 4 — HTTP/1.1 message viewer

Add an HTTP/1.1 message decoder that splits requests/responses into status line,
headers, and body, and renders them as readable text.

## Step 5 — Profile diff tool

Implement `diffProfiles` to walk two profile objects field-by-field and report
every path where values differ (cipher suites, extensions, pseudo-headers, …).

## Step 6 — Certificate inspector (parse + display X.509)

Implement `inspectCertificate`: parse DER or PEM, extract subject, issuer, SANs,
validity period, and SHA-256 fingerprint.

## Step 7 — Benchmark CLI

Wire `network-devtools bench` to the `@network/testing` benchmark suite so a
developer can run `network-devtools bench tls --iterations 100` from a terminal.

## Step 8 — Export (JSON/HTML reports)

Add exporters so an inspection session or profile diff can be written to JSON
or rendered as a self-contained HTML report for sharing.

## Definition of done

- [ ] TLS decoder decodes content type + handshake message type.
- [ ] HTTP/2 decoder decodes all nine frame types.
- [ ] TLS + HTTP/2 visualizers render readable ASCII traces.
- [ ] HTTP/1.1 viewer renders request/response messages.
- [ ] Profile diff reports every differing path.
- [ ] Certificate inspector extracts subject/issuer/SANs/fingerprint.
- [ ] `network-devtools bench` runs from the terminal.
- [ ] Sessions export to JSON and HTML.
- [ ] Every test in `tests/` passes; `tsc --build` is clean.
