# @auth-core/redis

Redis-backed `RevocationStore` and `SessionStore` implementations for
[`@auth-core/core`](https://www.npmjs.com/package/@auth-core/core), built on
[`ioredis`](https://github.com/redis/ioredis). Supports standalone,
Sentinel, and Cluster. Uses native Redis key TTLs, so revoked/expired
entries are reclaimed automatically — no sweep job required.

```bash
npm install @auth-core/redis ioredis
```

```ts
import { createAuth } from "@auth-core/core";
import { createRedisClient, RedisRevocationStore, RedisSessionStore } from "@auth-core/redis";

const client = createRedisClient({ mode: "standalone", options: { host: "localhost", port: 6379 } });

const auth = createAuth({
  // ...
  stores: {
    revocation: new RedisRevocationStore({ client }),
    session: new RedisSessionStore({ client }),
  },
});
```

Bring your own already-connected client for connection reuse across your
app:

```ts
import { Redis } from "ioredis";
const existing = new Redis(process.env.REDIS_URL!);
const client = createRedisClient({ mode: "instance", client: existing });
```

Full documentation: https://github.com/YOUR_GITHUB_ORG/auth-core
