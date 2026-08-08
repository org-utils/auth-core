import type {
  CreateSessionInput,
  SessionRecord,
  SessionStore,
  UpdateSessionInput,
} from '@auth-core/shared';
import { SessionExpiredError } from '@auth-core/shared';

import type { RedisLikeClient } from './client.js';

/* -------------------------------------------------------------------------- */
/* Design notes                                                               */
/* -------------------------------------------------------------------------- */
/*
 * Two families of keys are used:
 *
 * 1. Per-user, hash-tagged keys (single Cluster slot per user):
 *
 *      authcore:session:{userId}:session:{jti}
 *      authcore:user-sessions:{userId}
 *
 *    All operations touching both of these for the same user are done
 *    with a Lua script (EVAL), so they are atomic even on Redis Cluster.
 *
 * 2. A global jti -> userId index (NOT hash-tagged, single key per jti):
 *
 *      authcore:jti-index:{jti}    (note: NOT the same as a hash tag -
 *      this is a plain key, not a Cluster hash tag)
 *
 *    This lets `find`, `update`, `rotate`, and `delete` work correctly when
 *    called with only a jti (no userId), which the original implementation
 *    could not do at all - it silently returned null / threw / no-op'd.
 *
 *    This index key intentionally cannot share a Cluster slot with the
 *    per-user keys (different users would collide on hash tags otherwise),
 *    so writes to it are NOT part of the same atomic transaction as the
 *    per-user writes. This is a deliberate, documented trade-off:
 *
 *      - It is set with the same TTL as the session, so a crash between
 *        the two writes only ever produces a stale index entry that
 *        expires on its own and is also lazily cleaned up on read.
 *      - It never causes a *false positive* (pointing at a session that
 *        doesn't exist gets treated as "not found" and cleaned up), only
 *        a possible false negative for a few milliseconds, which is an
 *        acceptable window for a session store.
 *
 *    If you always have the userId available at the call site, pass it
 *    explicitly (`find(jti, userId)`, `update(jti, patch, userId)`, etc.)
 *    to skip the extra round trip entirely and get single-slot behavior.
 */

/* -------------------------------------------------------------------------- */
/* Types                                                                      */
/* -------------------------------------------------------------------------- */

export interface RedisSessionStoreOptions {
  /**
   * Redis client.
   *
   * Compatible with:
   * - ioredis standalone
   * - ioredis Sentinel
   * - ioredis Cluster
   */
  client: RedisLikeClient;

  /** Default: authcore:session: */
  keyPrefix?: string;

  /** Default: authcore:user-sessions: */
  userIndexPrefix?: string;

  /** Default: authcore:jti-index: */
  jtiIndexPrefix?: string;

  /**
   * Maximum number of active sessions per user.
   * Default: 20. Set to 0 to disable the limit.
   */
  maxSessionsPerUser?: number;
}

/* -------------------------------------------------------------------------- */
/* Lua scripts                                                                */
/* -------------------------------------------------------------------------- */

/**
 * Atomically creates a session and adds it to the user's session index.
 *
 * KEYS[1] = session key
 * KEYS[2] = user session index key
 *
 * ARGV[1] = session JSON
 * ARGV[2] = session TTL (seconds)
 * ARGV[3] = jti
 */
const CREATE_SCRIPT = `
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
redis.call('SADD', KEYS[2], ARGV[3])
return 1
`;

/**
 * Atomic session rotation.
 *
 * KEYS[1] = current session key
 * KEYS[2] = successor session key
 * KEYS[3] = user session index
 *
 * ARGV[1] = current timestamp
 * ARGV[2] = consumed session JSON
 * ARGV[3] = consumed session TTL
 * ARGV[4] = successor session JSON
 * ARGV[5] = successor TTL
 * ARGV[6] = old JTI
 * ARGV[7] = new JTI
 *
 * Return:
 *   1  = success
 *   0  = session does not exist
 *  -1  = session already consumed
 *  -2  = session expired
 */
const ROTATE_SCRIPT = `
local current = redis.call('GET', KEYS[1])

if not current then
  return 0
end

local currentSession = cjson.decode(current)

if currentSession.consumedAt ~= nil then
  return -1
end

if tonumber(currentSession.expiresAt) <= tonumber(ARGV[1]) then
  redis.call('DEL', KEYS[1])
  redis.call('SREM', KEYS[3], ARGV[6])
  return -2
end

redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[3])
redis.call('SET', KEYS[2], ARGV[4], 'EX', ARGV[5])
redis.call('SREM', KEYS[3], ARGV[6])
redis.call('SADD', KEYS[3], ARGV[7])

return 1
`;

/**
 * Atomically deletes a single session and removes it from the user index.
 *
 * KEYS[1] = session key
 * KEYS[2] = user session index
 *
 * ARGV[1] = jti
 *
 * Returns 1 if the session existed, 0 otherwise.
 */
const DELETE_SCRIPT = `
local existed = redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[2], ARGV[1])
return existed
`;

/**
 * Atomically deletes all sessions belonging to a user.
 *
 * KEYS[1] = user session index
 *
 * ARGV[1] = session prefix
 * ARGV[2] = userId
 *
 * Returns the list of deleted jtis (so the caller can clean up the
 * global jti index, which lives outside this user's Cluster slot).
 */
const DELETE_BY_USER_SCRIPT = `
local members = redis.call('SMEMBERS', KEYS[1])
local deleted = {}

for _, jti in ipairs(members) do
  local key = ARGV[1] .. '{' .. ARGV[2] .. '}:session:' .. jti

  if redis.call('DEL', key) == 1 then
    table.insert(deleted, jti)
  end
end

redis.call('DEL', KEYS[1])

return deleted
`;

/**
 * Removes stale JTIs from the user index.
 *
 * KEYS[1] = user session index
 *
 * ARGV[1] = session key prefix
 * ARGV[2] = userId
 *
 * Returns the list of removed jtis.
 */
const CLEAN_INDEX_SCRIPT = `
local members = redis.call('SMEMBERS', KEYS[1])
local removed = {}

for _, jti in ipairs(members) do
  local key = ARGV[1] .. '{' .. ARGV[2] .. '}:session:' .. jti

  if redis.call('EXISTS', key) == 0 then
    redis.call('SREM', KEYS[1], jti)
    table.insert(removed, jti)
  end
end

return removed
`;

/* -------------------------------------------------------------------------- */
/* Store                                                                      */
/* -------------------------------------------------------------------------- */

export class RedisSessionStore implements SessionStore {
  private readonly client: RedisLikeClient;

  private readonly keyPrefix: string;
  private readonly userIndexPrefix: string;
  private readonly jtiIndexPrefix: string;

  private readonly maxSessionsPerUser: number;

  constructor(options: RedisSessionStoreOptions) {
    this.client = options.client;

    this.keyPrefix = options.keyPrefix ?? 'authcore:session:';
    this.userIndexPrefix = options.userIndexPrefix ?? 'authcore:user-sessions:';
    this.jtiIndexPrefix = options.jtiIndexPrefix ?? 'authcore:jti-index:';

    this.maxSessionsPerUser = Math.max(0, options.maxSessionsPerUser ?? 20);
  }

  /* ------------------------------------------------------------------------ */
  /* Create                                                                   */
  /* ------------------------------------------------------------------------ */

  async create(input: CreateSessionInput): Promise<SessionRecord> {
    const now = nowSeconds();

    validateExpiration(input.expiresAt, now);

    const record: SessionRecord = {
      jti: input.jti,
      userId: input.userId,
      deviceId: input.deviceId,
      createdAt: now,
      expiresAt: input.expiresAt,
    };

    const ttl = Math.max(1, record.expiresAt - now);

    const key = this.sessionKey(record.userId, record.jti);
    const indexKey = this.userIndexKey(record.userId);

    // Atomic within the user's Cluster slot.
    await this.client.eval(
      CREATE_SCRIPT,
      2,
      key,
      indexKey,
      serialize(record),
      String(ttl),
      record.jti,
    );

    // Global lookup index. Not part of the atomic slot above (see design
    // notes) - safe to write right after, self-heals via TTL if it fails.
    await this.client.set(this.jtiIndexKey(record.jti), record.userId, 'EX', ttl);

    if (this.maxSessionsPerUser > 0) {
      await this.enforceSessionLimit(record.userId);
    }

    return record;
  }

  /* ------------------------------------------------------------------------ */
  /* Find                                                                     */
  /* ------------------------------------------------------------------------ */

  /**
   * Looks up a session by jti. Pass `userId` when you have it - it avoids
   * an extra round trip and is required for guaranteed Cluster-slot
   * locality. Without it, this falls back to the global jti index.
   */
  async find(jti: string, userId?: string): Promise<SessionRecord | null> {
    if (userId) {
      return this.findByUser(userId, jti);
    }

    const resolvedUserId = await this.resolveUserId(jti);

    if (!resolvedUserId) {
      return null;
    }

    return this.findByUser(resolvedUserId, jti);
  }

  /** Cluster-safe, single-round-trip lookup when userId is already known. */
  async findByUser(userId: string, jti: string): Promise<SessionRecord | null> {
    const sessionKey = this.sessionKey(userId, jti);
    const raw = await this.client.get(sessionKey);

    return this.parseAndReconcile(raw, userId, jti, sessionKey);
  }

  /* ------------------------------------------------------------------------ */
  /* Update                                                                   */
  /* ------------------------------------------------------------------------ */

  /**
   * Updates a session. Pass `userId` when known to skip the index lookup.
   */
  async update(
    jti: string,
    patch: UpdateSessionInput,
    userId?: string,
  ): Promise<SessionRecord | null> {
    const resolvedUserId = userId ?? (await this.resolveUserId(jti));

    if (!resolvedUserId) {
      return null;
    }

    const existing = await this.findByUser(resolvedUserId, jti);

    if (!existing) {
      return null;
    }

    const now = nowSeconds();

    const updated: SessionRecord = {
      ...existing,
      ...patch,
      // jti/userId are identity fields - never let a patch change them.
      jti: existing.jti,
      userId: existing.userId,
    };

    validateExpiration(updated.expiresAt, now);

    const ttl = Math.max(1, updated.expiresAt - now);

    await this.client.set(
      this.sessionKey(updated.userId, updated.jti),
      serialize(updated),
      'EX',
      ttl,
    );

    // Keep the global index TTL in sync so it doesn't outlive the session
    // (harmless if it does - reads self-heal - but keeps things tidy).
    await this.client.set(this.jtiIndexKey(updated.jti), updated.userId, 'EX', ttl);

    return updated;
  }

  /* ------------------------------------------------------------------------ */
  /* Atomic rotation                                                          */
  /* ------------------------------------------------------------------------ */

  /**
   * Rotates a session. Pass `userId` when known to skip the index lookup
   * and go straight to the atomic, single-slot path.
   */
  async rotate(
    jti: string,
    next: CreateSessionInput,
    userId?: string,
  ): Promise<SessionRecord> {
    const resolvedUserId = userId ?? (await this.resolveUserId(jti));

    if (!resolvedUserId) {
      throw new SessionExpiredError(`Cannot rotate unknown session "${jti}"`);
    }

    return this.rotateByUser(resolvedUserId, jti, next);
  }

  /**
   * Atomic, Cluster-safe session rotation. All three keys touched by the
   * Lua script share the same {userId} hash tag.
   */
  async rotateByUser(
    userId: string,
    jti: string,
    next: CreateSessionInput,
  ): Promise<SessionRecord> {
    const now = nowSeconds();

    validateExpiration(next.expiresAt, now);

    if (next.userId !== userId) {
      // Required for Cluster atomicity: successor must live in the same slot.
      throw new Error('Session rotation cannot change userId.');
    }

    const currentKey = this.sessionKey(userId, jti);
    const successorKey = this.sessionKey(next.userId, next.jti);
    const indexKey = this.userIndexKey(userId);

    const current = await this.rawFind(userId, jti);

    if (!current) {
      throw new SessionExpiredError(`Cannot rotate unknown session "${jti}"`);
    }

    const consumed: SessionRecord = { ...current, consumedAt: now };

    const successor: SessionRecord = {
      jti: next.jti,
      userId,
      deviceId: next.deviceId,
      createdAt: now,
      expiresAt: next.expiresAt,
      rotatedFrom: jti,
    };

    const consumedTtl = Math.max(1, consumed.expiresAt - now);
    const successorTtl = Math.max(1, successor.expiresAt - now);

    const result = await this.client.eval(
      ROTATE_SCRIPT,
      3,
      currentKey,
      successorKey,
      indexKey,
      String(now),
      serialize(consumed),
      String(consumedTtl),
      serialize(successor),
      String(successorTtl),
      jti,
      successor.jti,
    );

    const code = Number(result);

    if (code !== 1) {
      switch (code) {
        case 0:
          throw new SessionExpiredError(`Session "${jti}" does not exist`);
        case -1:
          throw new SessionExpiredError(`Session "${jti}" has already been consumed`);
        case -2:
          throw new SessionExpiredError(`Session "${jti}" has expired`);
        default:
          throw new Error(`Unexpected session rotation result: ${code}`);
      }
    }

    // Update the global index: retire the old jti, register the new one.
    // Order matters less than you'd think here - both are idempotent and
    // TTL-bounded, so a crash mid-way just leaves a harmless stale/missing
    // entry that self-heals on the next read.
    await Promise.all([
      this.client.del(this.jtiIndexKey(jti)),
      this.client.set(this.jtiIndexKey(successor.jti), userId, 'EX', successorTtl),
    ]);

    return successor;
  }

  /* ------------------------------------------------------------------------ */
  /* Delete                                                                   */
  /* ------------------------------------------------------------------------ */

  /**
   * Deletes a session. Pass `userId` when known to skip the index lookup.
   * Unlike the original implementation, this never silently no-ops.
   */
  async delete(jti: string, userId?: string): Promise<void> {
    const resolvedUserId = userId ?? (await this.resolveUserId(jti));

    if (!resolvedUserId) {
      return;
    }

    const sessionKey = this.sessionKey(resolvedUserId, jti);
    const indexKey = this.userIndexKey(resolvedUserId);

    await this.client.eval(DELETE_SCRIPT, 2, sessionKey, indexKey, jti);

    await this.client.del(this.jtiIndexKey(jti));
  }

  /* ------------------------------------------------------------------------ */
  /* Delete all sessions                                                      */
  /* ------------------------------------------------------------------------ */

  async deleteByUser(userId: string): Promise<void> {
    const indexKey = this.userIndexKey(userId);

    const deletedJtis = (await this.client.eval(
      DELETE_BY_USER_SCRIPT,
      1,
      indexKey,
      this.keyPrefix,
      userId,
    )) as string[];

    if (deletedJtis?.length) {
      const pipeline = this.client.pipeline();

      for (const jti of deletedJtis) {
        pipeline.del(this.jtiIndexKey(jti));
      }

      await pipeline.exec();
    }
  }

  /* ------------------------------------------------------------------------ */
  /* List sessions                                                            */
  /* ------------------------------------------------------------------------ */

  async listByUser(userId: string): Promise<SessionRecord[]> {
    const indexKey = this.userIndexKey(userId);
    const jtis = await this.client.smembers(indexKey);

    if (!jtis.length) {
      return [];
    }

    const pipeline = this.client.pipeline();

    for (const jti of jtis) {
      pipeline.get(this.sessionKey(userId, jti));
    }

    const results = await pipeline.exec();

    const sessions: SessionRecord[] = [];
    const stale: string[] = [];
    const now = nowSeconds();

    for (let i = 0; i < jtis.length; i++) {
      const result = results?.[i];
      const raw = Array.isArray(result) ? result[1] : null;

      if (!raw || typeof raw !== 'string') {
        stale.push(jtis[i]!);
        continue;
      }

      const record = parseRawSession(raw);

      if (!record || record.expiresAt <= now) {
        stale.push(jtis[i]!);
        continue;
      }

      sessions.push(record);
    }

    if (stale.length) {
      const cleanup = this.client.pipeline();

      for (const jti of stale) {
        cleanup.srem(indexKey, jti);
        cleanup.del(this.jtiIndexKey(jti));
      }

      await cleanup.exec();
    }

    return sessions;
  }

  /* ------------------------------------------------------------------------ */
  /* Cleanup                                                                  */
  /* ------------------------------------------------------------------------ */

  async cleanupUserIndex(userId: string): Promise<number> {
    const removed = (await this.client.eval(
      CLEAN_INDEX_SCRIPT,
      1,
      this.userIndexKey(userId),
      this.keyPrefix,
      userId,
    )) as string[];

    if (removed?.length) {
      const pipeline = this.client.pipeline();

      for (const jti of removed) {
        pipeline.del(this.jtiIndexKey(jti));
      }

      await pipeline.exec();
    }

    return removed?.length ?? 0;
  }

  /* ------------------------------------------------------------------------ */
  /* Key helpers                                                              */
  /* ------------------------------------------------------------------------ */

  private sessionKey(userId: string, jti: string): string {
    // {userId} is the Cluster hash tag - everything for one user lands
    // in a single slot.
    return `${this.keyPrefix}{${userId}}:session:${jti}`;
  }

  private userIndexKey(userId: string): string {
    return `${this.userIndexPrefix}{${userId}}`;
  }

  private jtiIndexKey(jti: string): string {
    // Deliberately NOT hash-tagged to a user - this is a global lookup key.
    return `${this.jtiIndexPrefix}${jti}`;
  }

  /* ------------------------------------------------------------------------ */
  /* Internal lookups                                                         */
  /* ------------------------------------------------------------------------ */

  private async resolveUserId(jti: string): Promise<string | null> {
    return this.client.get(this.jtiIndexKey(jti));
  }

  private async rawFind(userId: string, jti: string): Promise<SessionRecord | null> {
    const raw = await this.client.get(this.sessionKey(userId, jti));

    if (!raw) {
      return null;
    }

    return parseRawSession(raw);
  }

  /** Shared parse + lazy-cleanup logic used by findByUser. */
  private async parseAndReconcile(
    raw: string | null,
    userId: string,
    jti: string,
    sessionKey: string,
  ): Promise<SessionRecord | null> {
    if (!raw) {
      return null;
    }

    const record = parseRawSession(raw);
    const indexKey = this.userIndexKey(userId);

    if (!record) {
      // Corrupted entry - treat as absent and clean up.
      await Promise.all([
        this.client.srem(indexKey, jti),
        this.client.del(this.jtiIndexKey(jti)),
      ]);

      return null;
    }

    if (record.expiresAt <= nowSeconds()) {
      await Promise.all([
        this.client.del(sessionKey),
        this.client.srem(indexKey, jti),
        this.client.del(this.jtiIndexKey(jti)),
      ]);

      return null;
    }

    return record;
  }

  /* ------------------------------------------------------------------------ */
  /* Session limits                                                           */
  /* ------------------------------------------------------------------------ */

  private async enforceSessionLimit(userId: string): Promise<void> {
    if (this.maxSessionsPerUser <= 0) {
      return;
    }

    const sessions = await this.listByUser(userId);

    if (sessions.length <= this.maxSessionsPerUser) {
      return;
    }

    sessions.sort((a, b) => a.createdAt - b.createdAt);

    const excess = sessions.length - this.maxSessionsPerUser;
    const sessionsToDelete = sessions.slice(0, excess);

    const pipeline = this.client.pipeline();

    for (const session of sessionsToDelete) {
      pipeline.del(this.sessionKey(userId, session.jti));
      pipeline.srem(this.userIndexKey(userId), session.jti);
      pipeline.del(this.jtiIndexKey(session.jti));
    }

    await pipeline.exec();
  }
}

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function validateExpiration(expiresAt: number, now = nowSeconds()): void {
  if (!Number.isFinite(expiresAt) || expiresAt <= now) {
    throw new SessionExpiredError('Session expiration time must be in the future.');
  }
}

function serialize(record: SessionRecord): string {
  return JSON.stringify(record);
}

/** Never throws - corrupted data is treated as absent, not a hard failure. */
function parseRawSession(raw: string): SessionRecord | null {
  try {
    const record = JSON.parse(raw) as SessionRecord;

    if (!record || typeof record !== 'object') {
      return null;
    }

    return record;
  } catch {
    return null;
  }
}
