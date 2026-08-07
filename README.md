# @auth-core

A production-ready, **framework-agnostic** authentication core for Node.js and Bun, written in TypeScript.

It handles the parts of authentication that are the same no matter which HTTP
framework you use: password hashing, JWT issuance/verification, refresh
token rotation with reuse detection, and token/session revocation. It does
**not** contain Express/Fastify/Hono middleware, route handlers, or any
other HTTP-specific code — that stays in your application, a thin adapter
layer, or a separate `@auth-core/express` style package you build on top of
this one.

```bash
npm install @auth-core/core @auth-core/hashing @auth-core/jwt @auth-core/memory
# swap @auth-core/memory for @auth-core/redis in production
```

```ts
import { createAuth } from "@auth-core/core";
import { createArgon2Driver } from "@auth-core/hashing";
import { MemoryRevocationStore, MemorySessionStore } from "@auth-core/memory";

const auth = createAuth({
  hashing: { driver: createArgon2Driver() },
  jwt: {
    keys: [{ kid: "k1", algorithm: "HS256", privateKey: process.env.JWT_SECRET! }],
    issuer: "my-app",
    audience: "my-app-clients",
  },
  stores: {
    revocation: new MemoryRevocationStore(),
    session: new MemorySessionStore(),
  },
});

// Sign up
const passwordHash = await auth.hashPassword(rawPassword);

// Log in
const ok = await auth.verifyPassword(rawPassword, passwordHash);
const { accessToken, refreshToken } = await auth.login({ userId: user.id });

// Authenticate a request
const { sub: userId } = await auth.verifyAccessToken(accessToken);

// Refresh
const rotated = await auth.rotateRefreshToken(refreshToken);

// Log out
await auth.logoutAll(userId);
```

## Packages

| Package | Purpose |
|---|---|
| [`@auth-core/core`](./packages/auth-core) | Public `createAuth()` facade: config, orchestration, refresh rotation |
| [`@auth-core/jwt`](./packages/jwt) | Generic JWT signing/verification on top of [`jose`](https://github.com/panva/jose) |
| [`@auth-core/hashing`](./packages/hashing) | Argon2id/bcrypt password hashing + strength policy |
| [`@auth-core/shared`](./packages/shared) | Shared types and typed errors, used by every other package |
| [`@auth-core/memory`](./packages/memory) | In-memory `RevocationStore`/`SessionStore` — single process, dev/test |
| [`@auth-core/redis`](./packages/redis) | Redis-backed `RevocationStore`/`SessionStore` (standalone/sentinel/cluster) |

Install only the pieces you need. `@auth-core/core` depends on `shared`,
`hashing`, and `jwt`; storage adapters (`memory`/`redis`) are separate so the
core never has an opinion about your infrastructure.

## Documentation

- [Architecture](./docs/architecture.md) — package boundaries, design principles, why the core has no infra dependencies
- [Flows](./docs/flows.md) — login, refresh rotation, reuse detection, and revocation, step by step
- [Adapters](./docs/adapters.md) — implementing a custom `SessionStore`/`RevocationStore`/hashing driver
- [Security](./docs/security.md) — the security model and recommended production settings
- [Examples](./examples) — Express, Fastify, Hono, NestJS, Next.js, Bun

## Public API

```ts
const auth = createAuth(config);

await auth.hashPassword(password);
await auth.verifyPassword(password, hash);

await auth.signAccessToken(payload);
await auth.verifyAccessToken(token);
await auth.signRefreshToken(payload);
await auth.verifyRefreshToken(token);

await auth.signToken(payload);          // any custom token type
await auth.verifyToken(token);

await auth.login({ userId, deviceId });     // issues access+refresh, creates a session
await auth.rotateRefreshToken(refreshToken); // rotates with reuse detection

await auth.revokeToken(jti, expiresAt);
await auth.revokeUser(userId);
await auth.logout(sessionJti);
await auth.logoutAll(userId);
```

Every method is `async`. Every failure mode throws a typed error from
`@auth-core/shared` (`InvalidTokenError`, `ExpiredTokenError`,
`RevokedTokenError`, `RefreshReuseDetectedError`, `WeakPasswordError`, ...) —
never a generic `Error` — so your framework adapter can map errors to HTTP
status codes with a simple `switch`/`instanceof` check.

## Development

```bash
npm install       # installs and links all workspace packages
npm run build      # builds every package with tsup (ESM + CJS + .d.ts)
npm test           # runs the vitest suite (36 tests across all packages)
npm run typecheck  # tsc --noEmit across the whole workspace
```

## License

MIT

find packages -name "*.d.ts" -delete
find packages -name "*.d.mts" -delete
find packages -name "*.js" -delete
find packages -name "*.js.map" -delete
find packages -name "*.tsbuildinfo" -delete
rm -rf packages/*/dist
find packages -name "*.d.ts.map" -delete
