import type { RevocationRecord, RevocationStore } from "@auth-core/shared";
import type { RedisLikeClient } from "./client.js";

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
 */
export class RedisRevocationStore implements RevocationStore {
  private readonly client: RedisLikeClient;
  private readonly keyPrefix: string;

  constructor(options: RedisRevocationStoreOptions) {
    this.client = options.client;
    this.keyPrefix = options.keyPrefix ?? "authcore:revoked:";
  }

  async revoke(record: RevocationRecord): Promise<void> {
    const ttl = Math.max(1, record.expiresAt - nowSeconds());
    await this.client.set(this.key(record.jti), record.reason ?? "1", "EX", ttl);
  }

  async revokeMany(records: RevocationRecord[]): Promise<void> {
    if (records.length === 0) return;
    const pipeline = this.client.pipeline();
    const now = nowSeconds();
    for (const record of records) {
      const ttl = Math.max(1, record.expiresAt - now);
      pipeline.set(this.key(record.jti), record.reason ?? "1", "EX", ttl);
    }
    await pipeline.exec();
  }

  async isRevoked(jti: string): Promise<boolean> {
    const exists = await this.client.exists(this.key(jti));
    return exists === 1;
  }

  private key(jti: string): string {
    return `${this.keyPrefix}${jti}`;
  }
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}
