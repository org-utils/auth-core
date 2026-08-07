# Hono integration example.
Hono runs on Node, Bun, Cloudflare Workers, and
Deno unmodified — pair it with an edge-compatible SessionStore/
RevocationStore (e.g. Cloudflare KV, or Redis via a fetch-compatible
proxy) for a fully edge-deployed auth-core setup.

```ts
import { Hono } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import { createAuth, AuthError } from "@auth-core/core";
import { createArgon2Driver } from "@auth-core/hashing";
import { MemoryRevocationStore, MemorySessionStore } from "@auth-core/memory";

const auth = createAuth({
  hashing: { driver: createArgon2Driver() },
  jwt: {
    keys: [{ kid: "k1", algorithm: "HS256", privateKey: process.env.JWT_SECRET! }],
    issuer: "my-app",
    audience: "my-app-clients",
  },
  stores: { revocation: new MemoryRevocationStore(), session: new MemorySessionStore() },
});

const app = new Hono<{ Variables: { userId: string } }>();

app.onError((err, c) => {
  if (err instanceof AuthError) {
    return c.json({ error: err.code, message: err.message }, err.httpStatus as any);
  }
  return c.json({ error: "internal_error" }, 500);
});

const requireAuth = async (c: any, next: () => Promise<void>) => {
  const header = c.req.header("authorization");
  const token = header?.startsWith("Bearer ") ? header.slice(7) : undefined;
  if (!token) return c.json({ error: "missing_token" }, 401);

  const payload = await auth.verifyAccessToken(token); // throws -> caught by onError
  c.set("userId", payload.sub!);
  await next();
};

app.post("/login", async (c) => {
  const { userId } = await c.req.json<{ userId: string }>();
  const { accessToken, refreshToken } = await auth.login({ userId });
  setCookie(c, "refresh_token", refreshToken, { httpOnly: true, secure: true, sameSite: "Strict" });
  return c.json({ accessToken });
});

app.post("/refresh", async (c) => {
  const refreshToken = getCookie(c, "refresh_token");
  const rotated = await auth.rotateRefreshToken(refreshToken!);
  setCookie(c, "refresh_token", rotated.refreshToken, { httpOnly: true, secure: true, sameSite: "Strict" });
  return c.json({ accessToken: rotated.accessToken });
});

app.get("/me", requireAuth, (c) => c.json({ userId: c.get("userId") }));

export default app;
```
