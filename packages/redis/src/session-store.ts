import type { CreateSessionInput, SessionRecord, SessionStore, UpdateSessionInput } from "@auth-core/shared";
import { SessionExpiredError } from "@auth-core/shared";
import type { RedisLikeClient } from "./client.js";

export interface RedisSessionStoreOptions {
  client: RedisLikeClient;
  /** Key prefix for session records. Default: "authcore:session:". */
  keyPrefix?: string;
  /** Key prefix for the per-user index set. Default: "authcore:user-sessions:". */
  userIndexPrefix?: string;
}

/**
 * Redis-backed session store. Session records are stored as JSON strings
 * with a native TTL matching `expiresAt`, so abandoned sessions are
 * reclaimed by Redis without a sweep job. A per-user Set indexes each
 * user's active session jtis to support O(sessions) `deleteByUser` (used
 * by `logoutAll`).
 *
 * Only session *metadata* is stored here — never raw access/refresh tokens.
 */
export class RedisSessionStore implements SessionStore {
  private readonly client: RedisLikeClient;
  private readonly keyPrefix: string;
  private readonly userIndexPrefix: string;

  constructor(options: RedisSessionStoreOptions) {
    this.client = options.client;
    this.keyPrefix = options.keyPrefix ?? "authcore:session:";
    this.userIndexPrefix = options.userIndexPrefix ?? "authcore:user-sessions:";
  }

  async create(input: CreateSessionInput): Promise<SessionRecord> {
    const record: SessionRecord = {
      jti: input.jti,
      userId: input.userId,
      deviceId: input.deviceId,
      createdAt: nowSeconds(),
      expiresAt: input.expiresAt,
    };
    await this.persist(record);
    return record;
  }

  async update(jti: string, patch: UpdateSessionInput): Promise<SessionRecord | null> {
    const existing = await this.find(jti);
    if (!existing) return null;
    const updated: SessionRecord = { ...existing, ...patch };
    await this.persist(updated, { skipIndex: true });
    return updated;
  }

  async rotate(jti: string, next: CreateSessionInput): Promise<SessionRecord> {
    const existing = await this.rawFind(jti);
    if (!existing) {
      throw new SessionExpiredError(`Cannot rotate unknown session "${jti}"`);
    }

    const consumed: SessionRecord = { ...existing, consumedAt: nowSeconds() };
    const successor: SessionRecord = {
      jti: next.jti,
      userId: next.userId,
      deviceId: next.deviceId,
      createdAt: nowSeconds(),
      expiresAt: next.expiresAt,
      rotatedFrom: jti,
    };

    const pipeline = this.client.pipeline();
    const consumedTtl = Math.max(1, consumed.expiresAt - nowSeconds());
    pipeline.set(this.sessionKey(jti), JSON.stringify(consumed), "EX", consumedTtl);
    const successorTtl = Math.max(1, successor.expiresAt - nowSeconds());
    pipeline.set(this.sessionKey(successor.jti), JSON.stringify(successor), "EX", successorTtl);
    pipeline.sadd(this.userIndexKey(successor.userId), successor.jti);
    await pipeline.exec();

    return successor;
  }

  async delete(jti: string): Promise<void> {
    const existing = await this.rawFind(jti);
    if (!existing) return;
    const pipeline = this.client.pipeline();
    pipeline.del(this.sessionKey(jti));
    pipeline.srem(this.userIndexKey(existing.userId), jti);
    await pipeline.exec();
  }

  async deleteByUser(userId: string): Promise<void> {
    const jtis = await this.client.smembers(this.userIndexKey(userId));
    if (jtis.length === 0) return;
    const pipeline = this.client.pipeline();
    for (const jti of jtis) pipeline.del(this.sessionKey(jti));
    pipeline.del(this.userIndexKey(userId));
    await pipeline.exec();
  }

  async find(jti: string): Promise<SessionRecord | null> {
    return this.rawFind(jti);
  }

  private async rawFind(jti: string): Promise<SessionRecord | null> {
    const raw = await this.client.get(this.sessionKey(jti));
    if (!raw) return null;
    return JSON.parse(raw) as SessionRecord;
  }

  private async persist(record: SessionRecord, opts: { skipIndex?: boolean } = {}): Promise<void> {
    const ttl = Math.max(1, record.expiresAt - nowSeconds());
    const pipeline = this.client.pipeline();
    pipeline.set(this.sessionKey(record.jti), JSON.stringify(record), "EX", ttl);
    if (!opts.skipIndex) pipeline.sadd(this.userIndexKey(record.userId), record.jti);
    await pipeline.exec();
  }

  private sessionKey(jti: string): string {
    return `${this.keyPrefix}${jti}`;
  }

  private userIndexKey(userId: string): string {
    return `${this.userIndexPrefix}${userId}`;
  }
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}
