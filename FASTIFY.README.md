# Fastify integration example.

```ts
import Fastify from "fastify";
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

const app = Fastify();

// Central error handler: maps AuthError subclasses to their declared status.
app.setErrorHandler((err, _req, reply) => {
  if (err instanceof AuthError) {
    return reply.status(err.httpStatus).send({ error: err.code, message: err.message });
  }
  reply.status(500).send({ error: "internal_error" });
});

// A Fastify decorator acting as reusable "requireAuth" logic.
app.decorateRequest("userId", null);
app.addHook("onRequest", async (req, reply) => {
  if (!req.routeOptions.url?.startsWith("/protected")) return;

  const header = req.headers.authorization;
  const token = header?.startsWith("Bearer ") ? header.slice(7) : undefined;
  if (!token) return reply.status(401).send({ error: "missing_token" });

  const payload = await auth.verifyAccessToken(token); // throws -> caught by errorHandler
  (req as any).userId = payload.sub;
});

app.post("/login", async (req, reply) => {
  const { userId } = req.body as { userId: string };
  const { accessToken, refreshToken } = await auth.login({ userId });
  reply.setCookie("refresh_token", refreshToken, { httpOnly: true, secure: true, sameSite: "strict" });
  return { accessToken };
});

app.post("/refresh", async (req, reply) => {
  const refreshToken = req.cookies.refresh_token;
  const rotated = await auth.rotateRefreshToken(refreshToken!);
  reply.setCookie("refresh_token", rotated.refreshToken, { httpOnly: true, secure: true, sameSite: "strict" });
  return { accessToken: rotated.accessToken };
});

app.get("/protected/me", async (req) => {
  return { userId: (req as any).userId };
});

app.listen({ port: 3000 });
```
