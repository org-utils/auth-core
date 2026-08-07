import type { RevocationRecord, RevocationStore } from "@auth-core/shared";

/**
 * In-memory revocation store. Suitable for single-process deployments,
 * tests, and local development. Entries are swept lazily (on access) and
 * via an optional background interval so the map never grows unbounded.
 *
 * NOT suitable for multi-instance production deployments — use
 * `@auth-core/redis`'s RedisRevocationStore there, since revocation state
 * must be shared across every process handling requests.
 */
export class MemoryRevocationStore implements RevocationStore {
  private readonly store = new Map<string, number>(); // jti -> expiresAt (unix seconds)
  private sweepTimer?: ReturnType<typeof setInterval>;

  constructor(options: { sweepIntervalMs?: number } = {}) {
    const interval = options.sweepIntervalMs ?? 60_000;
    if (interval > 0) {
      this.sweepTimer = setInterval(() => this.sweep(), interval);
      this.sweepTimer.unref?.();
    }
  }

  async revoke(record: RevocationRecord): Promise<void> {
    this.store.set(record.jti, record.expiresAt);
  }

  async revokeMany(records: RevocationRecord[]): Promise<void> {
    for (const record of records) this.store.set(record.jti, record.expiresAt);
  }

  async isRevoked(jti: string): Promise<boolean> {
    const expiresAt = this.store.get(jti);
    if (expiresAt == null) return false;
    if (expiresAt <= nowSeconds()) {
      this.store.delete(jti);
      return false;
    }
    return true;
  }

  /** Removes expired entries. Called automatically on an interval; exposed for tests/manual GC. */
  sweep(): void {
    const now = nowSeconds();
    for (const [jti, expiresAt] of this.store) {
      if (expiresAt <= now) this.store.delete(jti);
    }
  }

  /** Stops the background sweep timer. Call this in tests/shutdown to avoid leaking timers. */
  close(): void {
    if (this.sweepTimer) clearInterval(this.sweepTimer);
  }

  get size(): number {
    return this.store.size;
  }
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}
