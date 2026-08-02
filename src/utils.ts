/**
 * Small shared helpers for @browsercore/devtools.
 */

import type { InspectorSessionId } from "./types.js";

/**
 * Exhaustiveness check for `switch`/`if-else` over discriminated unions.
 * Call in the `default` branch: `default: assertNever(x)`.
 * Adding a new union member forces every handler to compile-error until handled.
 */
export function assertNever(x: never): never {
    throw new Error(`Unexpected value: ${JSON.stringify(x)}`);
}

/** Generate a unique id with the given prefix (not cryptographically random). */
export function createId(prefix: "insp" = "insp"): string {
    return `${prefix}_${Date.now().toString(36)}_${Math.floor(Math.random() * 1e6).toString(36)}`;
}

/**
 * Create a branded {@link InspectorSessionId}. Centralises the only `as` cast
 * that produces the branded type, so the branding invariant lives in one place.
 */
export function createInspectorSessionId(): InspectorSessionId {
    return createId("insp") as InspectorSessionId;
}

/**
 * Wrap a caught value as `ErrorOptions`, or `undefined` when it isn't an
 * `Error`. Lets callers forward `cause` without repeating the
 * `cause === undefined ? undefined : { cause }` shape at every catch site.
 */
export function toErrorOptions(err: unknown): { cause: Error } | undefined {
    return err instanceof Error ? { cause: err } : undefined;
}
