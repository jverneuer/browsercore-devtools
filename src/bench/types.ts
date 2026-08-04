/**
 * BenchStats — summary statistics for a benchmark run.
 *
 * Vendored from @browsercore/testing so the bench command has no runtime
 * dependency on that package (its published benchmarks are stubs and its
 * manifest crashes on import in the shipped tarball).
 */
export interface BenchStats {
    readonly iterations: number;
    readonly avgMs: number;
    readonly p50: number;
    readonly p95: number;
    readonly p99: number;
}

/** Result of comparing two byte arrays (vendored from @browsercore/testing). */
export interface ComparisonResult {
    readonly matches: boolean;
    readonly divergenceByteIndex: number | undefined;
    readonly message: string;
}
