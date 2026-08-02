/**
 * CLI entry point — `network-devtools <command>`.
 *
 * Minimal, typed stub for now. Dispatch on the first positional, print help
 * when invoked with no args. Node-global access (process.argv, process.stdout)
 * is intentionally avoided so the module typechecks without @types/node.
 */

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
  bench      Run a benchmark

Run 'network-devtools <command> --help' for command-specific options.
`,
    );
}

/** Dispatch argv to the matching command (stubbed). */
export function _dispatch(
    argv: ReadonlyArray<string>,
    write: (line: string) => void = (line) => void line,
): void {
    const command = argv[2];
    if (!command || command === "--help" || command === "-h") {
        printHelp(write);
        return;
    }
    // PLAN: route to inspect / tls / http2 / diff / cert / bench.
    void command;
    throw new Error(`Unknown command '${command}' — see PLAN.md`);
}
