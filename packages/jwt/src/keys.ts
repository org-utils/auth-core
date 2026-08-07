import { ConfigurationError } from "@auth-core/shared";
import type { SigningKey } from "@auth-core/shared";

const SYMMETRIC_ALGS = new Set(["HS256", "HS384", "HS512"]);

export function isSymmetricAlgorithm(alg: string): boolean {
  return SYMMETRIC_ALGS.has(alg);
}

/**
 * Holds the set of configured signing keys and resolves which one to use
 * for signing (the "current" key) or verifying (by `kid`, falling back to
 * trying every configured key when no `kid` is present in the header —
 * needed for zero-downtime key rotation).
 *
 * Key material handling:
 * - For symmetric algorithms (HS256/384/512) `privateKey` may be a plain
 *   `string` secret or a `Uint8Array`; it is encoded automatically.
 * - For asymmetric algorithms (RS, ES, EdDSA) `privateKey`/`publicKey` must
 *   already be `jose`-compatible key objects (import them once at startup
 *   with `jose`'s `importPKCS8`/`importSPKI`/`importJWK`) — this package
 *   does not guess PEM vs. JWK encoding for you.
 */
export class KeyRing {
  private readonly keys = new Map<string, SigningKey>();
  private currentKid: string;

  constructor(keys: SigningKey[], currentKid?: string) {
    if (keys.length === 0) {
      throw new ConfigurationError("At least one signing key must be configured");
    }
    for (const key of keys) this.keys.set(key.kid, key);

    this.currentKid = currentKid ?? keys[keys.length - 1]!.kid;
    if (!this.keys.has(this.currentKid)) {
      throw new ConfigurationError(`currentKid "${this.currentKid}" is not among the configured keys`);
    }
  }

  get current(): SigningKey {
    return this.keys.get(this.currentKid)!;
  }

  byKid(kid: string): SigningKey | undefined {
    return this.keys.get(kid);
  }

  all(): SigningKey[] {
    return [...this.keys.values()];
  }

  setCurrent(kid: string): void {
    if (!this.keys.has(kid)) {
      throw new ConfigurationError(`Cannot set current key: unknown kid "${kid}"`);
    }
    this.currentKid = kid;
  }
}

/** Resolves a signing/verification key into whatever `jose` expects for its algorithm. */
export function resolveKeyMaterial(key: SigningKey, part: "privateKey" | "publicKey"): Uint8Array {
  const raw = key[part];
  if (raw == null) {
    throw new ConfigurationError(`Signing key "${key.kid}" is missing ${part}`);
  }
  if (isSymmetricAlgorithm(key.algorithm)) {
    if (raw instanceof Uint8Array) return raw;
    if (typeof raw === "string") return new TextEncoder().encode(raw);
    throw new ConfigurationError(
      `Symmetric key "${key.kid}" must be a string secret or Uint8Array, got ${typeof raw}`,
    );
  }
  // Asymmetric algorithms: pass the pre-imported jose key object straight through.
  // jose types this as KeyLike/CryptoKey; kept loosely typed at this boundary
  // since importPKCS8/importSPKI/importJWK live outside this module.
  return raw as unknown as Uint8Array;
}
