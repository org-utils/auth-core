# Flows

## Login

```
POST /login
  │
  ▼
auth.verifyPassword(password, storedHash)
  │  (if needsRehash was true on a prior check, re-hash and persist)
  ▼
auth.login({ userId, deviceId })
  │
  ├─ signs an access token (type: "access", short TTL)
  ├─ signs a refresh token (type: "refresh", long TTL, fresh jti)
  └─ sessionStore.create({ jti, userId, deviceId, expiresAt })
  │
  ▼
{ accessToken, refreshToken }  → returned to the client
```

The session store record is keyed by the **refresh token's** `jti`. Access
tokens are stateless and are not tracked in the session store at all —
verifying one only checks the signature, expiry, and the revocation store
(for the rare case an access token needs to be killed immediately, e.g. an
admin-initiated revocation).

## Refresh token rotation

```
old refresh token
       │
       ▼
1. jwtService.verifyRefreshToken(token)      → throws on bad signature / expiry
       │
       ▼
2. revocationStore.isRevoked(jti)?           → throws RevokedTokenError if true
       │
       ▼
3. sessionStore.find(jti)                    → throws SessionExpiredError if missing
       │
       ▼
4. session.consumedAt already set?  ───yes──▶  REUSE DETECTED (see below)
       │ no
       ▼
5. issue new access token (fresh jti)
6. issue new refresh token (fresh jti)
       │
       ▼
7. sessionStore.rotate(oldJti, newSessionInput)
       │   atomically: marks old session consumedAt=now,
       │   creates the successor session with rotatedFrom=oldJti
       ▼
8. hooks.onRefresh({ oldJti, newJti, userId })
       │
       ▼
{ accessToken, refreshToken }  → returned to the client
```

Each refresh token is **one-time use**. A client that refreshes twice in a
race (e.g. two tabs both refreshing near expiry) will have one request
succeed and the other hit the reuse-detection path below — by design, since
distinguishing "legitimate retry" from "stolen token" is not reliably
possible from the server side alone. Structure your client to serialize
refresh calls (a single in-flight promise shared across tabs/requests) to
avoid this.

## Reuse detection

If a refresh token whose session is already `consumedAt`-marked is
presented again, that's a strong signal the token was stolen and used by
both the legitimate client and an attacker (or replayed from a stale
client-side cache):

```
session.consumedAt is set
       │
       ▼
hooks.onReuseDetected({ jti, userId })   ← alert/log this; it's a security event
       │
       ▼
sessionStore.deleteByUser(userId)        ← kill every session, not just this one
revocationStore.revoke({ jti, ... })
       │
       ▼
throw RefreshReuseDetectedError
```

The entire session family for the user is torn down, not just the reused
token — a stolen refresh token could have already been rotated by the
attacker into a newer one you don't know about, so the only safe response
is to force a full re-login on every device.

Disable this with `session.reuseDetection: false` only if you have a
specific reason to (e.g. you're doing your own reuse handling upstream);
it's on by default.

## Revocation

Four call sites, one mechanism (`RevocationStore.revoke`/`revokeMany`):

| Trigger | Call |
|---|---|
| User logs out of one device | `auth.logout(sessionJti)` |
| User logs out everywhere | `auth.logoutAll(userId)` |
| Password changed | `auth.revokeUser(userId)` (call after rehashing the new password) |
| Admin/security action | `auth.revokeToken(jti, expiresAt)` |

`logout`/`logoutAll` operate on the **session store** (refresh-token
sessions) and also record a revocation entry so an in-flight access token
tied to that session is rejected immediately rather than living out its
remaining TTL. `revokeToken` is the low-level primitive — it works for any
jti, access or refresh, session-backed or not (e.g. a one-off
`password-reset` token you want to invalidate after it's used once).

Revocation entries carry their own `expiresAt` so adapters (in particular
the Redis one) can set a native TTL and never accumulate stale entries.
