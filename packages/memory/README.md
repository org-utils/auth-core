# @auth-core/memory

In-memory `RevocationStore` and `SessionStore` implementations for
[`@auth-core/core`](https://www.npmjs.com/package/@auth-core/core) — single
process only (development, tests, or a single-instance deployment).

For anything running more than one process/instance, use
[`@auth-core/redis`](https://www.npmjs.com/package/@auth-core/redis) instead
— revocation and session state must be shared across every process handling
requests.

```bash
npm install @auth-core/memory
```

```ts
import { createAuth } from "@auth-core/core";
import { MemoryRevocationStore, MemorySessionStore } from "@auth-core/memory";

const auth = createAuth({
  // ...
  stores: {
    revocation: new MemoryRevocationStore(),
    session: new MemorySessionStore(),
  },
});
```

Full documentation: https://github.com/YOUR_GITHUB_ORG/auth-core
