# @auth-core/hashing

Argon2id (default) and bcrypt (optional) password hashing drivers, plus a
configurable password-strength policy, behind a uniform `PasswordService`.

```bash
npm install @auth-core/hashing
```

```ts
import { PasswordService, createArgon2Driver } from "@auth-core/hashing";

const passwords = new PasswordService({
  driver: createArgon2Driver({ memoryCost: 19456, timeCost: 2, parallelism: 1 }),
  policy: { minLength: 10, requireUppercase: true, requireNumber: true },
});

const hash = await passwords.hash("a-strong-password-1");
const { valid, needsRehash } = await passwords.verify("a-strong-password-1", hash);
```

Usually consumed indirectly through
[`@auth-core/core`](https://www.npmjs.com/package/@auth-core/core)'s
`auth.hashPassword()` / `auth.verifyPassword()`, but works standalone if you
only need password hashing.

Full documentation, including how to write a custom hashing driver:
https://github.com/YOUR_GITHUB_ORG/auth-core/blob/main/docs/adapters.md
