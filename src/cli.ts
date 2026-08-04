/**
 * CLI entry point — `network-devtools <command>`.
 *
 * Dispatch on the first positional, print help when invoked with no args.
 * Capture files are read synchronously via `readFileSync`; `process.argv` /
 * `process.stdout` are not touched at module scope so dispatch stays testable.
 */

import { readFileSync } from "node:fs";
import { createInspectorSession } from "./inspector/inspector.js";
import { visualizeTlsHandshake, visualizeHttp2Stream } from "./visualizer/visualizer.js";
import { diffProfiles } from "./diff/profileDiff.js";
import { inspectCertificate } from "./cert/certInspector.js";
import { benchmarkTlsHandshake, benchmarkHttp2Request, type BenchStats } from "./bench/index.js";
import type { InspectionSession, PacketProtocol } from "./types.js";
import type { ProfileId } from "@browsercore/profiles";

/** Print usage. */
function printHelp(write: (line: string) => void): void {
    write(
        `network-devtools

Usage:
  network-devtools <command> [options]

Commands:
  inspect    Inspect a packet capture file
  tls        Visualize a TLS handshake
  http2      Visualize an HTTP/2 session
  diff       Diff two browser profiles
  cert       Inspect an X.509 certificate
  bench      Run protocol benchmarks

Bench flags:
  --tls              Run only the TLS handshake fingerprint benchmark
  --http2            Run only the HTTP/2 comparison + compression benchmark
  -n, --iterations N  Repetitions per benchmark (default ${DEFAULT_ITERATIONS})

Run 'network-devtools <command> --help' for command-specific options.
`,
    );
}

/** Read a capture file into a single-frame session of the given protocol. */
function inspectCapture(capturePath: string, protocol: PacketProtocol): InspectionSession {
    const bytes = readFileSync(capturePath);
    const session = createInspectorSession();
    session.addFrame({ direction: "sent", protocol, bytes, decoded: null });
    return session;
}

/** `inspect <capture>` — summarize a capture file. */
function cmdInspect(argv: ReadonlyArray<string>, write: (line: string) => void): void {
    const capturePath = argv[3];
    if (capturePath === undefined) {
        write("inspect: missing <capture> path");
        return;
    }
    const session = inspectCapture(capturePath, "tcp");
    write(`Session ${session.id}`);
    write(`frames: ${session.frames.length}`);
    const first = session.frames[0];
    if (first !== undefined) {
        write(`bytes:  ${first.bytes.length}`);
    }
}

/** `tls <capture>` — visualize a TLS handshake. */
function cmdTls(argv: ReadonlyArray<string>, write: (line: string) => void): void {
    const capturePath = argv[3];
    if (capturePath === undefined) {
        write("tls: missing <capture> path");
        return;
    }
    const session = inspectCapture(capturePath, "tls");
    write(visualizeTlsHandshake(session));
}

/** `http2 <capture>` — visualize an HTTP/2 session. */
function cmdHttp2(argv: ReadonlyArray<string>, write: (line: string) => void): void {
    const capturePath = argv[3];
    if (capturePath === undefined) {
        write("http2: missing <capture> path");
        return;
    }
    const session = inspectCapture(capturePath, "http2");
    write(visualizeHttp2Stream(session));
}

/** `diff <a> <b>` — diff two browser profiles by id. */
function cmdDiff(argv: ReadonlyArray<string>, write: (line: string) => void): void {
    const a = argv[3];
    const b = argv[4];
    if (a === undefined || b === undefined) {
        write("diff: requires <profile-a> <profile-b>");
        return;
    }
    const result = diffProfiles(a as ProfileId, b as ProfileId);
    write(`Diff ${result.profileA} vs ${result.profileB}: ${result.differences.length} change(s)`);
    for (const entry of result.differences) {
        write(`  ${entry.path}: ${JSON.stringify(entry.a)} -> ${JSON.stringify(entry.b)}`);
    }
}

/** `cert <file>` — inspect an X.509 certificate. */
function cmdCert(argv: ReadonlyArray<string>, write: (line: string) => void): void {
    const certPath = argv[3];
    if (certPath === undefined) {
        write("cert: missing <cert> path");
        return;
    }
    const info = inspectCertificate(readFileSync(certPath));
    write(`Subject: ${info.subject}`);
    write(`Issuer:  ${info.issuer}`);
    write(`Valid:   ${info.notBefore.toISOString()} -> ${info.notAfter.toISOString()}`);
    write(`SAN:     ${info.san.join(", ") || "(none)"}`);
    write(`SHA-256: ${info.fingerprintSha256}`);
}

/** Default iteration count for a bench run. */
const DEFAULT_ITERATIONS = 100;

/** Parse bench flags from argv[3..]. Returns the iteration count and which suites to run. */
function parseBenchFlags(argv: ReadonlyArray<string>): {
    iterations: number;
    runTls: boolean;
    runHttp2: boolean;
} {
    let iterations = DEFAULT_ITERATIONS;
    let tls = false;
    let http2 = false;
    let pick = false;

    for (let i = 3; i < argv.length; i++) {
        const arg = argv[i];
        if (arg === "--tls" || arg === "--http2") {
            pick = true;
            if (arg === "--tls") {
                tls = true;
            } else {
                http2 = true;
            }
        } else if (arg === "--iterations" || arg === "-n") {
            const next = argv[i + 1];
            if (next === undefined) {
                throw new Error(`bench: '${arg}' requires a number`);
            }
            const n = Number(next);
            if (!Number.isFinite(n) || n < 1) {
                throw new Error(`bench: invalid iteration count '${next}'`);
            }
            iterations = Math.floor(n);
            i++;
        } else {
            throw new Error(`bench: unknown flag '${arg}' — see 'network-devtools bench --help'`);
        }
    }

    return { iterations, runTls: tls || !pick, runHttp2: http2 || !pick };
}

/** Format a single benchmark result block. */
function formatBenchResult(label: string, stats: BenchStats, write: (line: string) => void): void {
    write(`${label} (${stats.iterations} iterations):`);
    write(`  avg: ${stats.avgMs.toFixed(4)} ms`);
    write(`  p50: ${stats.p50.toFixed(4)} ms`);
    write(`  p95: ${stats.p95.toFixed(4)} ms`);
    write(`  p99: ${stats.p99.toFixed(4)} ms`);
}

/** `bench` — run protocol benchmarks (vendored from @browsercore/testing). */
function cmdBench(argv: ReadonlyArray<string>, write: (line: string) => void): void {
    const { iterations, runTls, runHttp2 } = parseBenchFlags(argv);
    let first = true;
    if (runTls) {
        if (!first) {
            write("");
        }
        first = false;
        write("TLS ClientHello fingerprint:");
        formatBenchResult("  ja3+ja4", benchmarkTlsHandshake(iterations), write);
    }
    if (runHttp2) {
        if (!first) {
            write("");
        }
        first = false;
        write("HTTP/2 golden comparison + gzip round-trip:");
        formatBenchResult("  compare+compress", benchmarkHttp2Request(iterations), write);
    }
}

/** Dispatch argv to the matching command. */
export function dispatch(
    argv: ReadonlyArray<string>,
    write: (line: string) => void = (line) => void line,
): void {
    const command = argv[2];
    if (command === undefined || command === "--help" || command === "-h") {
        printHelp(write);
        return;
    }
    switch (command) {
        case "inspect":
            cmdInspect(argv, write);
            break;
        case "tls":
            cmdTls(argv, write);
            break;
        case "http2":
            cmdHttp2(argv, write);
            break;
        case "diff":
            cmdDiff(argv, write);
            break;
        case "cert":
            cmdCert(argv, write);
            break;
        case "bench":
            cmdBench(argv, write);
            break;
        default:
            throw new Error(`Unknown command '${command}' — see 'network-devtools --help'`);
    }
}
