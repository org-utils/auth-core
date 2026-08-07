# @auth-core/shared

Shared TypeScript types and typed error classes used by every `@auth-core/*`
package: `RevocationStore`, `SessionStore`, `SigningKey`, `TokenPayload`,
`AuthHooks`, and the `AuthError` hierarchy (`InvalidTokenError`,
`ExpiredTokenError`, `RevokedTokenError`, `RefreshReuseDetectedError`,
`WeakPasswordError`, etc).

You normally don't install this directly — it's a dependency of
[`@auth-core/core`](https://www.npmjs.com/package/@auth-core/core),
[`@auth-core/jwt`](https://www.npmjs.com/package/@auth-core/jwt), and
[`@auth-core/hashing`](https://www.npmjs.com/package/@auth-core/hashing).
Install it directly only if you're implementing a custom storage adapter or
hashing driver and need the interfaces without pulling in the rest.

```bash
npm install @auth-core/shared
```

```ts
import { RevokedTokenError, type SessionStore } from "@auth-core/shared";
```

Full documentation: https://github.com/YOUR_GITHUB_ORG/auth-core
