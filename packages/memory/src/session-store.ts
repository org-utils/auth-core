import type { CreateSessionInput, SessionRecord, SessionStore, UpdateSessionInput } from "@auth-core/shared";
import { SessionExpiredError } from "@auth-core/shared";

/**
 * In-memory session store for single-process deployments, tests, and local
 * development. Use `@auth-core/redis`'s RedisSessionStore for anything
 * running more than one instance.
 */
export class MemorySessionStore implements SessionStore {
  private readonly byJti = new Map<string, SessionRecord>();
  private readonly byUser = new Map<string, Set<string>>();

  async create(input: CreateSessionInput): Promise<SessionRecord> {
    const record: SessionRecord = {
      jti: input.jti,
      userId: input.userId,
      deviceId: input.deviceId,
      createdAt: Math.floor(Date.now() / 1000),
      expiresAt: input.expiresAt,
    };
    this.put(record);
    return record;
  }

  async update(jti: string, patch: UpdateSessionInput): Promise<SessionRecord | null> {
    const existing = this.byJti.get(jti);
    if (!existing) return null;
    const updated: SessionRecord = { ...existing, ...patch };
    this.byJti.set(jti, updated);
    return updated;
  }

  async rotate(jti: string, next: CreateSessionInput): Promise<SessionRecord> {
    const existing = this.byJti.get(jti);
    if (!existing) {
      throw new SessionExpiredError(`Cannot rotate unknown session "${jti}"`);
    }
    this.byJti.set(jti, { ...existing, consumedAt: Math.floor(Date.now() / 1000) });

    const successor: SessionRecord = {
      jti: next.jti,
      userId: next.userId,
      deviceId: next.deviceId,
      createdAt: Math.floor(Date.now() / 1000),
      expiresAt: next.expiresAt,
      rotatedFrom: jti,
    };
    this.put(successor);
    return successor;
  }

  async delete(jti: string): Promise<void> {
    const record = this.byJti.get(jti);
    if (!record) return;
    this.byJti.delete(jti);
    this.byUser.get(record.userId)?.delete(jti);
  }

  async deleteByUser(userId: string): Promise<void> {
    const jtis = this.byUser.get(userId);
    if (!jtis) return;
    for (const jti of jtis) this.byJti.delete(jti);
    this.byUser.delete(userId);
  }

  async find(jti: string): Promise<SessionRecord | null> {
    const record = this.byJti.get(jti);
    if (!record) return null;
    if (record.expiresAt <= Math.floor(Date.now() / 1000)) {
      await this.delete(jti);
      return null;
    }
    return record;
  }

  private put(record: SessionRecord): void {
    this.byJti.set(record.jti, record);
    let set = this.byUser.get(record.userId);
    if (!set) {
      set = new Set();
      this.byUser.set(record.userId, set);
    }
    set.add(record.jti);
  }

  get size(): number {
    return this.byJti.size;
  }
}
