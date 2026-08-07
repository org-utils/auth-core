# Security recommendations

## Signing keys

- Prefer **asymmetric algorithms (ES256 or EdDSA)** over HS256 in any
  system where more than one service needs to *verify* tokens but only one
  should be able to *issue* them — the verifying services only ever hold
  the public key. Use HS256 only when a single trusted process does both
  signing and verification.
- Generate signing keys with the tooling `jose` provides
  (`generateKeyPair`), not hand-rolled key material.
- Rotate keys by adding a new one with a new `kid` and setting
  `currentKid` to it — old tokens signed with the previous key remain
  verifiable (via `KeyRing.byKid`) until they expire, so rotation never
  needs a "grace period" hack.
- Store the private key outside source control and outside the database —
  environment variables backed by a secrets manager (AWS Secrets Manager,
  GCP Secret Manager, Vault) at minimum.

## Password hashing

- Argon2id (the default driver) is the OWASP-recommended choice as of
  2025. The default parameters (`memoryCost: 19456` / 19 MiB,
  `timeCost: 2`, `parallelism: 1`) match OWASP's minimum recommendation —
  raise `memoryCost` if your infrastructure can afford it; more memory cost
  is the most effective lever against GPU/ASIC cracking.
- A `pepper` (a secret held outside the database, mixed into every hash) is
  supported but is not a substitute for a strong per-password salt (which
  Argon2id/bcrypt already generate automatically) — treat it as
  defense-in-depth against a database-only leak, not your primary control.
- Never lower `timeCost`/`memoryCost` to "fix" login latency under load;
  scale hashing horizontally (it's stateless and embarrassingly
  parallel) instead of weakening it.

## Refresh tokens

- Reuse detection (`session.reuseDetection`, on by default) is your primary
  defense against a stolen refresh token being used silently alongside the
  legitimate one — wire `hooks.onReuseDetected` to an alerting pipeline,
  not just a log line, since it indicates a likely compromise in progress.
- Keep refresh token TTL as short as your UX tolerates. 30 days is a
  reasonable default for a "remember me" style session; for anything
  handling sensitive data, consider hours-to-days instead.
- Bind sessions to a `deviceId` (a stable, client-generated identifier —
  not a fingerprint you compute server-side) so `logout()` can target one
  device without affecting others, and so an unexpected new `deviceId`
  attempting to rotate an existing session is a signal worth surfacing to
  the user ("new sign-in from an unrecognized device").

## Access tokens

- Keep access token TTL short (the 15-minute default is a reasonable
  starting point) — they are not checked against the session store on
  every verification for performance reasons, only against the
  (fast, TTL'd) revocation store, so a short TTL bounds how long a
  compromised-but-not-yet-revoked access token remains useful.
- If you need instant, guaranteed revocation of a specific access token
  (not just eventual expiry), call `auth.revokeToken(jti, exp)` — the
  revocation store is checked on every `verifyAccessToken` call.

## Clock skew and validation

- The default `clockToleranceSeconds: 5` accommodates minor clock drift
  across a distributed fleet without meaningfully weakening `exp`/`nbf`
  enforcement. Don't raise it beyond what your infrastructure's actual NTP
  drift requires.
- Always configure `issuer`/`audience` in production and let the library
  validate them — an unscoped JWT (no `aud` check) that leaks from one
  service's logs remains usable against every other service trusting the
  same signing key.

## Transport and storage

- Refresh tokens should be delivered as `HttpOnly`, `Secure`,
  `SameSite=Strict` (or `Lax`, depending on your redirect flows) cookies
  wherever the client is a browser — never `localStorage`, which is
  readable by any script on the page (XSS-exposed).
- This library never persists raw tokens server-side (see
  [adapters.md](./adapters.md)) — only `jti` and metadata — specifically so
  that a session-store leak alone cannot be used to forge requests.
