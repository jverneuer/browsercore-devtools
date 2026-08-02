# @network/devtools

Developer tooling — packet inspector, TLS handshake visualizer, HTTP/2 frame
viewer, profile diff, certificate inspector, and benchmark CLI. Depends on the
library but is NOT required by it.

## Responsibility

Make protocol behavior observable and debuggable during development. Every
tool here consumes the public API of the lower-level packages; nothing here is
imported by them.

## Tools

- **Packet inspector** — capture and inspect raw protocol frames by direction
  and protocol.
- **TLS handshake visualizer** — render a captured TLS handshake as a
  human-readable ASCII trace.
- **HTTP/2 frame viewer** — decode and display HTTP/2 frames (SETTINGS,
  HEADERS, DATA, WINDOW_UPDATE, …).
- **Profile diff** — compare two browser profiles field-by-field.
- **Certificate inspector** — parse and display an X.509 certificate's subject,
  issuer, SANs, and fingerprint.
- **Benchmark CLI** — run latency/throughput benchmarks from the terminal via
  `network-devtools bench`.

## Public API

```ts
import {
    createInspectorSession,
    visualizeTlsHandshake,
    diffProfiles,
    inspectCertificate,
    DevtoolsError,
} from "@network/devtools";

const session = createInspectorSession();
session.addFrame({
    direction: "sent",
    protocol: "tls",
    bytes: clientHello,
    decoded: null,
});
console.log(session.frames.length);

// Compare two profiles:
const diff = diffProfiles("chrome-140" as never, "firefox-135" as never);
console.log(diff.differences);
```

## Types

| Export | Kind | Purpose |
| --- | --- | --- |
| `createInspectorSession()` | function | Start an empty inspection session |
| `decodeTlsRecord()` | function | Decode a TLS record (stubbed) |
| `decodeHttp2Frame()` | function | Decode an HTTP/2 frame (stubbed) |
| `visualizeTlsHandshake()` | function | Render a TLS trace (stubbed) |
| `visualizeHttp2Stream()` | function | Render an HTTP/2 trace (stubbed) |
| `diffProfiles()` | function | Diff two browser profiles (stubbed) |
| `inspectCertificate()` | function | Parse an X.509 certificate (stubbed) |
| `InspectionSession` | interface | Live session with frames + filter |
| `PacketFrame` | interface | A single captured frame |
| `CertInfo` | interface | Parsed certificate summary |
| `DevtoolsError` | class | Base typed error |

## Dependency graph

```
@network/devtools
  └─ @network/fetch  @network/http2  @network/http1  @network/cookies
        └─ @network/profiles  @network/tls  @network/crypto
              └─ @network/transport
                    └─ node:net / node:crypto
```

`@network/devtools` sits at the very top — it depends on everything and nothing
depends on it.
