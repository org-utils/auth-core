import type { RevocationRecord, RevocationStore } from '@auth-core/shared';

import type { RedisLikeClient } from './client.js';

export interface RedisRevocationStoreOptions {
  client: RedisLikeClient;
  /** Key prefix, so multiple apps can share a Redis instance safely. Default: "authcore:revoked:". */
  keyPrefix?: string;
}

/**
 * Redis-backed revocation store. Each revoked jti is stored as
 * `{prefix}{jti} -> reason`, with the Redis key TTL itself set to the
 * token's remaining lifetime — expired entries are reclaimed automatically
 * by Redis, no sweep job required.
 *
 * Every operation here is a single-key command, so this store works
 * identically on standalone, Sentinel, and Cluster with no hash tags
 * required (unlike the session store, there's no multi-key atomicity
 * requirement to satisfy).
 */
export class RedisRevocationStore implements RevocationStore {
  private readonly client: RedisLikeClient;
  private readonly keyPrefix: string;

  constructor(options: RedisRevocationStoreOptions) {
    this.client = options.client;
    this.keyPrefix = options.keyPrefix ?? 'authcore:revoked:';
  }

  /* ------------------------------------------------------------------------ */
  /* Revoke                                                                   */
  /* ------------------------------------------------------------------------ */

  async revoke(record: RevocationRecord): Promise<void> {
    const ttl = computeTtl(record);

    await this.client.set(this.key(record.jti), record.reason ?? '1', 'EX', ttl);
  }

  async revokeMany(records: RevocationRecord[]): Promise<void> {
    if (records.length === 0) return;

    // Validate every record up front - fail before issuing any network
    // calls rather than partway through a batch.
    const ttls = records.map((record) => computeTtl(record));

    const pipeline = this.client.pipeline();

    for (let i = 0; i < records.length; i++) {
      pipeline.set(this.key(records[i]!.jti), records[i]!.reason ?? '1', 'EX', ttls[i]!);
    }

    const results = await pipeline.exec();

    // pipeline.exec() resolves to [error, result][] - a failed command does
    // NOT reject the pipeline promise. Since a silently-missed revocation is
    // a security bug (a token believed revoked is actually still valid), we
    // check every result explicitly rather than trusting a resolved promise.
    const failures: { jti: string; error: unknown }[] = [];

    for (let i = 0; i < records.length; i++) {
      const result = results?.[i];
      const error = Array.isArray(result) ? result[0] : undefined;

      if (error) {
        failures.push({ jti: records[i]!.jti, error });
      }
    }

    if (failures.length > 0) {
      throw new RevocationBatchError(failures);
    }
  }

  /* ------------------------------------------------------------------------ */
  /* Check                                                                    */
  /* ------------------------------------------------------------------------ */

  async isRevoked(jti: string): Promise<boolean> {
    const exists = await this.client.exists(this.key(jti));
    return exists === 1;
  }

  /**
   * Batched revocation check - one network round trip instead of N.
   * Useful for validating a whole family of rotated tokens, or a batch
   * of refresh attempts, at once.
   */
  async isRevokedMany(jtis: string[]): Promise<Set<string>> {
    if (jtis.length === 0) return new Set();

    const pipeline = this.client.pipeline();

    for (const jti of jtis) {
      pipeline.exists(this.key(jti));
    }

    const results = await pipeline.exec();

    const revoked = new Set<string>();

    for (let i = 0; i < jtis.length; i++) {
      const result = results?.[i];
      const error = Array.isArray(result) ? result[0] : undefined;
      const value = Array.isArray(result) ? result[1] : undefined;

      if (error) {
        // Fail closed: if we can't confirm a jti's status, don't silently
        // treat it as "not revoked".
        throw new RevocationBatchError([{ jti: jtis[i]!, error }]);
      }

      if (value === 1) {
        revoked.add(jtis[i]!);
      }
    }

    return revoked;
  }

  private key(jti: string): string {
    return `${this.keyPrefix}${jti}`;
  }
}

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/**
 * Validates and computes the Redis TTL for a revocation record.
 *
 * Throws early with a clear message instead of letting a malformed
 * `expiresAt` (undefined/NaN/etc.) turn into `Math.max(1, NaN) === NaN`,
 * which would otherwise reach Redis as an invalid `EX` argument and fail
 * with an opaque "value is not an integer" error deep inside the client.
 */
function computeTtl(record: RevocationRecord, now = nowSeconds()): number {
  if (!Number.isFinite(record.expiresAt)) {
    throw new Error(
      `Cannot revoke jti "${record.jti}": expiresAt must be a finite number, got ${String(
        record.expiresAt,
      )}.`,
    );
  }

  return Math.max(1, record.expiresAt - now);
}

/**
 * Thrown by revokeMany/isRevokedMany when one or more pipelined commands
 * fail. Carries the specific jtis that failed so callers can retry or
 * alert on exactly what wasn't revoked/checked, rather than guessing.
 */
export class RevocationBatchError extends Error {
  readonly failures: { jti: string; error: unknown }[];

  constructor(failures: { jti: string; error: unknown }[]) {
    super(
      `Redis revocation batch operation failed for ${failures.length} jti(s): ${failures
        .map((f) => f.jti)
        .join(', ')}`,
    );

    this.name = 'RevocationBatchError';
    this.failures = failures;
  }
}
