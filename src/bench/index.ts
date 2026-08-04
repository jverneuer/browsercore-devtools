/**
 * Barrel for the vendored benchmark + fingerprint modules.
 *
 * Mirrors the subset of @browsercore/testing's public API that the bench
 * command consumes, so cli.ts imports read identically.
 */
export { benchmarkTlsHandshake, benchmarkHttp2Request } from "./bench.js";
export { computeJa3 } from "./ja3.js";
export { computeJa4 } from "./ja4.js";
export type { BenchStats } from "./types.js";
