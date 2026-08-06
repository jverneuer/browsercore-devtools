/**
 * File-system provider abstraction for the benchmark + CLI modules (Rule 21).
 *
 * These modules depend on this interface — never on `node:fs`/`node:path`
 * directly — so the backend is replaceable (test double, in-memory FS,
 * etc.) and the call paths stay unit-testable without touching the real
 * filesystem.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Minimal file-system abstraction: read a file whole and join path segments.
 * Higher layers depend on this interface — never on a concrete implementation.
 */
export interface FileSystemProvider {
    /** Read an entire file into a byte array. */
    readFileSync(path: string): Uint8Array;
    /** Join path segments using the platform separator. */
    join(...parts: readonly string[]): string;
}

/** {@link FileSystemProvider} backed by Node's native `node:fs`/`node:path`. */
export class NodeFileSystemProvider implements FileSystemProvider {
    readFileSync(path: string): Uint8Array {
        return readFileSync(path);
    }
    join(...parts: readonly string[]): string {
        return join(...parts);
    }
}

/**
 * Default singleton — the file-system backend the benchmark + CLI modules call
 * into. Tests can swap this for a fake provider to exercise file-dependent
 * paths without the real filesystem.
 */
export const fsProvider: FileSystemProvider = new NodeFileSystemProvider();
