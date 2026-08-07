# @auth-core/jwt

Generic JWT signing and verification built on [`jose`](https://github.com/panva/jose).
Supports arbitrary token types (not just access/refresh), all common
algorithms (HS/RS/ES/EdDSA), multi-key rotation, and typed errors.

```bash
npm install @auth-core/jwt
```

```ts
import { JwtService } from "@auth-core/jwt";

const jwt = new JwtService({
  keys: [{ kid: "k1", algorithm: "HS256", privateKey: process.env.JWT_SECRET! }],
  issuer: "my-app",
  audience: "my-app-clients",
});

const accessToken = await jwt.signAccessToken({ sub: userId });
const payload = await jwt.verifyAccessToken(accessToken);

// Any custom token type works through the generic API:
const resetToken = await jwt.signToken({ sub: userId, type: "password-reset" }, 600);
await jwt.verifyToken(resetToken, { expectedClaims: { type: "password-reset" } });
```

Usually consumed indirectly through
[`@auth-core/core`](https://www.npmjs.com/package/@auth-core/core), but
works standalone if you only need JWTs without sessions/rotation/hashing.

Full documentation: https://github.com/YOUR_GITHUB_ORG/auth-core
