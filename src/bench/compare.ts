/**
 * Byte comparison helpers — vendored from @browsercore/testing utils.
 */

import type { ComparisonResult } from "./types.js";

/** Format bytes as a lowercase hex string with no separators. */
export function bytesToHex(buf: Uint8Array): string {
    let out = "";
    for (const byte of buf) {
        out += byte.toString(16).padStart(2, "0");
    }
    return out;
}

/**
 * Compare two byte arrays. Returns a {@link ComparisonResult} reporting whether
 * they match, the first divergence index (if any), and a message.
 */
export function compareBytes(a: Uint8Array, b: Uint8Array): ComparisonResult {
    if (a.length !== b.length) {
        return {
            matches: false,
            divergenceByteIndex: Math.min(a.length, b.length),
            message: `Length mismatch: ${a.length} vs ${b.length}`,
        };
    }
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) {
            return {
                matches: false,
                divergenceByteIndex: i,
                message: `Byte ${i}: 0x${bytesToHex(a.subarray(i, i + 1))} vs 0x${bytesToHex(b.subarray(i, i + 1))}`,
            };
        }
    }
    return {
        matches: true,
        divergenceByteIndex: undefined,
        message: "equal",
    };
}
