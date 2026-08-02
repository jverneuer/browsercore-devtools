/**
 * Profile diff tool — compare two browser profiles field-by-field.
 *
 * Walks both `BrowserProfile` values structurally and reports every leaf that
 * differs, with a JSON-pointer-ish path and both sides' values. Unknown profile
 * ids surface as {@link ProfileDiffError} (wrapping the underlying
 * {@link UnknownProfileError} from @browsercore/profiles).
 */

import { getProfile, UnknownProfileError } from "@browsercore/profiles";
import { ProfileDiffError } from "../errors.js";
import type { ProfileDiff, ProfileDiffEntry } from "../types.js";
import type { ProfileId } from "@browsercore/profiles";

/** Compare two scalar values for equality (handles primitives + Date). */
function leafEqual(a: unknown, b: unknown): boolean {
    if (a instanceof Date && b instanceof Date) {
        return a.getTime() === b.getTime();
    }
    return a === b;
}

/**
 * Recursively compare two values, emitting a {@link ProfileDiffEntry} for every
 * leaf that differs. Paths use "/" separators (e.g. "tls/cipherSuites/2").
 */
function diffLeaves(
    path: string,
    a: unknown,
    b: unknown,
    out: ProfileDiffEntry[],
): void {
    if (leafEqual(a, b)) {
        return;
    }
    if (a instanceof Date || b instanceof Date) {
        out.push({ path, a, b });
        return;
    }
    if (Array.isArray(a) && Array.isArray(b)) {
        const len = Math.max(a.length, b.length);
        for (let i = 0; i < len; i++) {
            const hasA = i < a.length;
            const hasB = i < b.length;
            if (!hasA || !hasB) {
                out.push({
                    path: `${path}/${i}`,
                    a: hasA ? a[i] : "<missing>",
                    b: hasB ? b[i] : "<missing>",
                });
                continue;
            }
            diffLeaves(`${path}/${i}`, a[i], b[i], out);
        }
        return;
    }
    if (isPlainObject(a) && isPlainObject(b)) {
        const keys = new Set<string>([
            ...Object.keys(a as Record<string, unknown>),
            ...Object.keys(b as Record<string, unknown>),
        ]);
        for (const key of Array.from(keys).sort()) {
            const childA = (a as Record<string, unknown>)[key];
            const childB = (b as Record<string, unknown>)[key];
            const childPath = path === "" ? key : `${path}/${key}`;
            if (childA === undefined) {
                out.push({ path: childPath, a: "<missing>", b: childB });
                continue;
            }
            if (childB === undefined) {
                out.push({ path: childPath, a: childA, b: "<missing>" });
                continue;
            }
            diffLeaves(childPath, childA, childB, out);
        }
        return;
    }
    out.push({ path, a, b });
}

/** True for non-null, non-array, non-Date object values. */
function isPlainObject(v: unknown): v is Record<string, unknown> {
    return (
        typeof v === "object" &&
        v !== null &&
        !Array.isArray(v) &&
        !(v instanceof Date)
    );
}

/** Diff two profiles and return every field that differs. */
export function diffProfiles(a: ProfileId, b: ProfileId): ProfileDiff {
    try {
        const profileA = getProfile(a);
        const profileB = getProfile(b);
        const differences: ProfileDiffEntry[] = [];
        diffLeaves("", profileA, profileB, differences);
        return { profileA: a, profileB: b, differences };
    } catch (err) {
        if (err instanceof UnknownProfileError) {
            throw new ProfileDiffError(err.message, { cause: err });
        }
        if (err instanceof ProfileDiffError) {
            throw err;
        }
        const cause = err instanceof Error ? err : undefined;
        const message = `failed to diff profiles: ${err instanceof Error ? err.message : String(err)}`;
        throw new ProfileDiffError(message, cause === undefined ? undefined : { cause });
    }
}
