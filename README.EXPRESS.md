# Express integration example.
Auth-core has no knowledge of Express — this file is the entire "adapter":
pulling the bearer token out of the request, calling into `auth`, and
mapping thrown AuthError subclasses to HTTP responses.

```ts
import express, { type NextFunction, type Request, type Response } from "express";
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

// Extend Express's Request type with the authenticated user id.
declare module "express-serve-static-core" {
  interface Request {
    userId?: string;
  }
}

/** Middleware: requires a valid access token, sets req.userId. */
async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  const token = header?.startsWith("Bearer ") ? header.slice(7) : undefined;
  if (!token) return res.status(401).json({ error: "missing_token" });

  try {
    const payload = await auth.verifyAccessToken(token);
    req.userId = payload.sub;
    next();
  } catch (err) {
    next(err);
  }
}

/** Central error handler: maps every AuthError to its declared httpStatus. */
function authErrorHandler(err: unknown, _req: Request, res: Response, next: NextFunction) {
  if (err instanceof AuthError) {
    return res.status(err.httpStatus).json({ error: err.code, message: err.message });
  }
  next(err);
}

const app = express();
app.use(express.json());

app.post("/login", async (req: Request, res:Response, next: NextFunction) => {
  try {
    const { accessToken, refreshToken } = await auth.login({ userId: req.body.userId });
    res.cookie("refresh_token", refreshToken, { httpOnly: true, secure: true, sameSite: "strict" });
    res.json({ accessToken });
  } catch (err) {
    next(err);
  }
});

app.post("/refresh", async (req: Request, res: Response, next: NextFunction) => {
  try {
    const rotated = await auth.rotateRefreshToken(req.cookies.refresh_token);
    res.cookie("refresh_token", rotated.refreshToken, { httpOnly: true, secure: true, sameSite: "strict" });
    res.json({ accessToken: rotated.accessToken });
  } catch (err) {
    next(err);
  }
});

app.get("/me", requireAuth, (req: Request, res: Response) => {
  res.json({ userId: req.userId });
});

app.use(authErrorHandler);

app.listen(3000);
```
