/**
 * Cryptographic provider abstraction for the fingerprint modules (Rule 21).
 *
 * The JA3/JA4 fingerprint modules depend on this interface — never on
 * `node:crypto` directly — so the backend is replaceable (test double,
 * WebCrypto, etc.) and the fingerprint logic stays I/O-free and unit-testable
 * against synthetic byte streams.
 */

import { createHash } from "node:crypto";

/** Hash algorithms required by the fingerprint modules. */
export type HashAlgorithm = "md5" | "sha256";

/**
 * Pure hashing abstraction. Higher layers depend on this interface — never on
 * a concrete provider — so the backend stays swappable.
 */
export interface CryptoProvider {
    /** Compute the digest of `data` under `algorithm`, returned as raw bytes. */
    hash(algorithm: HashAlgorithm, data: Uint8Array): Uint8Array;
}

/** {@link CryptoProvider} backed by Node's native `node:crypto` module. */
export class NodeCryptoProvider implements CryptoProvider {
    hash(algorithm: HashAlgorithm, data: Uint8Array): Uint8Array {
        return createHash(algorithm).update(data).digest();
    }
}

/**
 * Factory that returns the default {@link CryptoProvider} backed by
 * `node:crypto`. Centralizes the choice of hashing backend so callers can
 * swap the implementation in one place.
 */
export function createCryptoProvider(): CryptoProvider {
    return new NodeCryptoProvider();
}
