# Architecture

## Design principles

1. **The core has no infrastructure opinions.** `@auth-core/core` never
   imports Redis, a database driver, or anything else that talks over a
   network. It depends only on `@auth-core/shared`'s interfaces
   (`RevocationStore`, `SessionStore`) and receives concrete
   implementations through dependency injection at `createAuth(config)`
   time. This is what lets the same core run identically in a
   single-process dev server and a horizontally-scaled fleet behind Redis
   Cluster — you change the adapter passed into `stores`, nothing else.

2. **Framework independence.** Nothing in this repository imports Express,
   Fastify, or any other HTTP framework. `verifyAccessToken()` takes a raw
   token string and returns a payload or throws — how you get the token out
   of a request (`Authorization` header, cookie, custom header) and how you
   turn a thrown error into an HTTP response is left to your application or
   a thin adapter layer. See [examples](../examples) for the ~10 lines that
   glues each framework to the core.

3. **Errors are typed, not stringly-typed.** Every failure path throws a
   subclass of `AuthError` with a stable `.code` and `.httpStatus`. Callers
   can `instanceof`-check for the specific failure they care about
   (`RefreshReuseDetectedError` vs. plain `ExpiredTokenError`) instead of
   parsing error messages.

4. **Storage adapters store metadata, never tokens.** `SessionStore` records
   `{ jti, userId, deviceId, createdAt, expiresAt }` — never the raw JWT.
   This means a leaked session-store backup cannot be used to forge
   requests; the signing key is the only secret that matters.

## Package graph

```
                     ┌────────────────┐
                     │ @auth-core/core │
                     └───────┬────────┘
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
   ┌────────────────┐ ┌─────────────┐ ┌──────────────┐
   │ @auth-core/jwt  │ │ …/hashing   │ │  …/shared    │
   └───────┬─────────┘ └──────┬──────┘ └──────┬───────┘
           │                  │               ▲
           └──────────────────┴───────────────┘
                     (both depend on shared's
                      types/errors)

     Storage adapters implement @auth-core/shared's interfaces
     and are wired in by the *application*, not by the core:

   ┌─────────────────┐        ┌─────────────────┐
   │ @auth-core/memory│  or   │ @auth-core/redis │
   └─────────────────┘        └─────────────────┘
           implements RevocationStore + SessionStore
```

`@auth-core/core` has a **compile-time** dependency on `jwt`, `hashing`, and
`shared` (it needs their classes to construct the facade), but only an
**interface-level** dependency on storage — it imports the `RevocationStore`
and `SessionStore` *types* from `shared`, never a concrete adapter package.

## Why a monorepo of small packages instead of one package with peer deps?

- **Tree-shaking**: an app that only ever issues one-off tokens (no
  sessions/rotation) can depend on `@auth-core/jwt` alone and never pull in
  `argon2` or `ioredis`.
- **Independent versioning**: a Redis adapter bugfix ships without bumping
  the core's version, so consumers pinned to `@auth-core/core@1.x` aren't
  forced to also take unrelated Redis changes.
- **Explicit infra boundary**: it's structurally impossible for the core to
  accidentally import `ioredis`, because it's not a dependency of that
  package at all — `npm ls ioredis` from `packages/auth-core` returns
  nothing.

## Module format

Every package ships both ESM (`dist/index.js`) and CommonJS
(`dist/index.cjs`) builds plus `.d.ts` declarations, built with `tsup`. The
`exports` field in each `package.json` points `require()` at the CJS build
and `import` at the ESM build, so the library works unmodified in both
`"type": "module"` and CommonJS Node projects, and in Bun.
