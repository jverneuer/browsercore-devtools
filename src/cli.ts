#!/usr/bin/env node
/**
 * CLI entry point — `network-devtools <command>`.
 *
 * Dispatch on the first positional, print help when invoked with no args.
 * Capture files are read synchronously via `readFileSync`; `process.argv` /
 * `process.stdout` are touched only in the bottom entry-point guard, so
 * dispatch stays testable when the module is imported elsewhere.
 */

import { readFileSync } from "node:fs";
import { createInspectorSession } from "./inspector/inspector.js";
import { visualizeTlsHandshake, visualizeHttp2Stream } from "./visualizer/visualizer.js";
import { diffProfiles } from "./diff/profileDiff.js";
import { inspectCertificate } from "./cert/certInspector.js";
// Import the bench module by relative path rather than from the
// `@browsercore/testing` root: the root re-exports the 17 test-category
// suites, whose `it.todo()` stubs would otherwise register with vitest and
// leak into every suite that imports this file. The bench module has no
// dependency on that barrel. A relative path (not a bare subpath) also
// bypasses the package's `exports` map, so the compiled CLI resolves it at
// runtime without `@browsercore/testing` having to expose a `/bench` subpath.
import { benchmarkTlsHandshake, benchmarkHttp2Request } from "../../testing/dist/bench/bench.js";
import type { BenchStats } from "../../testing/dist/types.js";
import type { InspectionSession, PacketProtocol } from "./types.js";
import type { ProfileId } from "@browsercore/profiles";

/** Which protocol a `bench` target exercises. */
type BenchTarget = "tls" | "http2";

/** Default repetitions for a benchmark run (overridable via `--iterations`). */
const DEFAULT_BENCH_ITERATIONS = 100;

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
  bench      Benchmark protocol parsing against golden captures

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

/**
 * Parse the trailing options of a `bench` argv slice (`[target, ...opts]`),
 * returning the target, iteration count, and optional profile. Throws on a
 * malformed `--iterations` value so the CLI fails fast instead of silently
 * running a bogus number of repetitions.
 */
function parseBenchOpts(argv: ReadonlyArray<string>): {
    iterations: number;
    profile: string | undefined;
} {
    let iterations = DEFAULT_BENCH_ITERATIONS;
    let profile: string | undefined;
    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        if (arg === "--iterations") {
            const raw = argv[i + 1];
            if (raw === undefined) {
                throw new Error("bench: --iterations requires a value");
            }
            const n = Number(raw);
            if (!Number.isFinite(n) || !Number.isInteger(n) || n < 1) {
                throw new Error(`bench: --iterations must be a positive integer (got '${raw}')`);
            }
            iterations = n;
            i++;
        } else if (arg === "--profile") {
            const raw = argv[i + 1];
            if (raw === undefined) {
                throw new Error("bench: --profile requires a value");
            }
            profile = raw;
            i++;
        } else if (arg !== undefined) {
            throw new Error(`bench: unknown option '${arg}'`);
        }
    }
    return { iterations, profile };
}

/** Format a `BenchStats` result as a multi-line, human-readable summary. */
function formatBenchStats(label: string, stats: BenchStats): string {
    const fmt = (ms: number) => `${ms.toFixed(3)} ms`;
    return [
        `Benchmark: ${label} (${stats.iterations} iterations)`,
        `  avg: ${fmt(stats.avgMs)}`,
        `  p50: ${fmt(stats.p50)}`,
        `  p95: ${fmt(stats.p95)}`,
        `  p99: ${fmt(stats.p99)}`,
    ].join("\n");
}

/** `bench <tls|http2> [--iterations N] [--profile P]` — run a protocol benchmark. */
function cmdBench(argv: ReadonlyArray<string>, write: (line: string) => void): void {
    const target = argv[3] as BenchTarget | undefined;
    if (target === undefined) {
        write("bench: requires <tls|http2> — see 'network-devtools bench --help'");
        return;
    }
    if (target !== "tls" && target !== "http2") {
        throw new Error(`bench: unknown target '${target}' — expected 'tls' or 'http2'`);
    }
    const { iterations, profile } = parseBenchOpts(argv.slice(4));
    // `exactOptionalPropertyTypes` forbids passing `profile: undefined` for a
    // `profile?: string` parameter, so build the options object conditionally
    // and omit the key entirely when no `--profile` was given.
    const options = profile === undefined ? undefined : { profile };
    if (target === "tls") {
        const stats = benchmarkTlsHandshake(iterations, options);
        write(formatBenchStats("tls-client-hello-fingerprint", stats));
        return;
    }
    const stats = benchmarkHttp2Request(iterations, options);
    write(formatBenchStats("http2-settings-comparison", stats));
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

// Entry point when run as the `network-devtools` binary. Guarded so importing
// this module (e.g. from tests) does not trigger a dispatch at module load.
if (process.argv[1] !== undefined && import.meta.url === `file://${process.argv[1]}`) {
    dispatch(process.argv, (line) => {
        process.stdout.write(`${line}\n`);
    });
}
