# Bun integration example, using `Bun.serve` (no framework).
Every auth-core package is Bun-compatible since it's built on Web Crypto
and standard Node APIs Bun implements natively.

Run with: 
```bash
bun run examples/bun.ts
```

```ts
import { createAuth, AuthError } from "@auth-core/core";
import { createArgon2Driver } from "@auth-core/hashing";
import { MemoryRevocationStore, MemorySessionStore } from "@auth-core/memory";

const auth = createAuth({
  hashing: { driver: createArgon2Driver() },
  jwt: {
    keys: [{ kid: "k1", algorithm: "HS256", privateKey: Bun.env.JWT_SECRET! }],
    issuer: "my-app",
    audience: "my-app-clients",
  },
  stores: { revocation: new MemoryRevocationStore(), session: new MemorySessionStore() },
});

function errorResponse(err: unknown): Response {
  if (err instanceof AuthError) {
    return Response.json({ error: err.code, message: err.message }, { status: err.httpStatus });
  }
  return Response.json({ error: "internal_error" }, { status: 500 });
}

Bun.serve({
  port: 3000,
  async fetch(req) {
    const url = new URL(req.url);

    if (url.pathname === "/login" && req.method === "POST") {
      const { userId } = await req.json();
      const { accessToken, refreshToken } = await auth.login({ userId });
      const res = Response.json({ accessToken });
      res.headers.append(
        "Set-Cookie",
        `refresh_token=${refreshToken}; HttpOnly; Secure; SameSite=Strict; Path=/`,
      );
      return res;
    }

    if (url.pathname === "/refresh" && req.method === "POST") {
      const cookie = req.headers.get("cookie") ?? "";
      const refreshToken = /refresh_token=([^;]+)/.exec(cookie)?.[1];
      if (!refreshToken) return Response.json({ error: "missing_token" }, { status: 401 });

      try {
        const rotated = await auth.rotateRefreshToken(refreshToken);
        const res = Response.json({ accessToken: rotated.accessToken });
        res.headers.append(
          "Set-Cookie",
          `refresh_token=${rotated.refreshToken}; HttpOnly; Secure; SameSite=Strict; Path=/`,
        );
        return res;
      } catch (err) {
        return errorResponse(err);
      }
    }

    if (url.pathname === "/me" && req.method === "GET") {
      const token = req.headers.get("authorization")?.replace("Bearer ", "");
      if (!token) return Response.json({ error: "missing_token" }, { status: 401 });

      try {
        const payload = await auth.verifyAccessToken(token);
        return Response.json({ userId: payload.sub });
      } catch (err) {
        return errorResponse(err);
      }
    }

    return new Response("Not found", { status: 404 });
  },
});
```
