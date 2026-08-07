# Adapter guide

## Custom `SessionStore` / `RevocationStore`

Both interfaces live in `@auth-core/shared` and have no dependency on any
particular database. Implement them against whatever you already run —
Postgres, DynamoDB, Cloudflare KV, etc.

```ts
import type { RevocationStore, RevocationRecord } from "@auth-core/shared";

export class PostgresRevocationStore implements RevocationStore {
  constructor(private db: Pool) {}

  async revoke(record: RevocationRecord): Promise<void> {
    await this.db.query(
      `insert into revoked_tokens (jti, expires_at, reason)
       values ($1, to_timestamp($2), $3)
       on conflict (jti) do update set expires_at = excluded.expires_at`,
      [record.jti, record.expiresAt, record.reason ?? null],
    );
  }

  async revokeMany(records: RevocationRecord[]): Promise<void> {
    await Promise.all(records.map((r) => this.revoke(r)));
  }

  async isRevoked(jti: string): Promise<boolean> {
    const { rowCount } = await this.db.query(
      `select 1 from revoked_tokens where jti = $1 and expires_at > now()`,
      [jti],
    );
    return (rowCount ?? 0) > 0;
  }
}
```

Requirements for a correct `RevocationStore`:

- `isRevoked` must return `false` once `expiresAt` has passed — either by
  filtering expired rows on read (as above) or by physically deleting them
  (a native TTL, a cron sweep, whatever fits your store).
- `revoke`/`revokeMany` should be idempotent — calling `revoke` twice for
  the same `jti` must not error.

Requirements for a correct `SessionStore`:

- `rotate(oldJti, next)` must be effectively atomic from the caller's
  perspective: once it returns, both "old session marked consumed" and
  "new session exists" must be true, or the reuse-detection guarantee in
  [flows.md](./flows.md) breaks. A single transaction (SQL) or a Lua
  script/`MULTI` (Redis) satisfies this; the in-memory adapter gets it for
  free from JS's single-threaded execution.
- Never persist the raw access or refresh token string — only `jti` and
  metadata. The JWT signature is what makes the token trustworthy; storing
  the token itself just creates a second copy of a bearer credential to
  leak.
- `find` should behave as if expired sessions don't exist (return `null`),
  whether that's enforced by a `WHERE expires_at > now()` clause or a
  native TTL.

## Custom hashing driver

Implement `HashingDriver` from `@auth-core/hashing` to add an algorithm
beyond the built-in Argon2id/bcrypt drivers (for example, to support
verifying legacy hashes from a previous auth system during a migration):

```ts
import type { HashingDriver } from "@auth-core/hashing";
import { scrypt as scryptCb, randomBytes, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCb);

export function createScryptDriver(): HashingDriver {
  return {
    name: "scrypt",

    async hash(password: string): Promise<string> {
      const salt = randomBytes(16);
      const derived = (await scrypt(password, salt, 64)) as Buffer;
      return `$scrypt$${salt.toString("hex")}$${derived.toString("hex")}`;
    },

    async verify(password: string, hash: string): Promise<boolean> {
      const [, , saltHex, hashHex] = hash.split("$");
      const salt = Buffer.from(saltHex, "hex");
      const expected = Buffer.from(hashHex, "hex");
      const derived = (await scrypt(password, salt, expected.length)) as Buffer;
      return timingSafeEqual(derived, expected);
    },

    needsRehash: () => false,
    recognizes: (hash: string) => hash.startsWith("$scrypt$"),
  };
}
```

Register it as a `legacyDriver` so `PasswordService` can still verify old
hashes while every new hash uses your primary (presumably Argon2id) driver:

```ts
new PasswordService({
  driver: createArgon2Driver(),
  legacyDrivers: [createScryptDriver()],
});
```

`PasswordService.verify()` will report `needsRehash: true` for anything
verified through a legacy driver, so a typical login handler transparently
upgrades the stored hash:

```ts
const { valid, needsRehash } = await auth.password.verify(rawPassword, user.passwordHash);
if (valid && needsRehash) {
  user.passwordHash = await auth.hashPassword(rawPassword);
  await db.users.update(user);
}
```
