import { randomUUID } from "node:crypto";
import type { JwtService } from "@auth-core/jwt";
import type { RevocationStore, SessionStore, TokenPayload, AuthHooks } from "@auth-core/shared";
import { RefreshReuseDetectedError, RevokedTokenError, SessionExpiredError } from "@auth-core/shared";

export interface RefreshRotationDeps {
  jwt: JwtService;
  sessionStore: SessionStore;
  revocationStore: RevocationStore;
  hooks: AuthHooks;
  accessTtlSeconds: number;
  refreshTtlSeconds: number;
  reuseDetection: boolean;
}

export interface RotateResult {
  accessToken: string;
  refreshToken: string;
  payload: TokenPayload;
}

/**
 * Validates and rotates a refresh token:
 *
 *   old refresh token -> validate -> issue new access token -> issue new
 *   refresh token -> invalidate previous refresh token
 *
 * Reuse detection: if the presented token's `jti` maps to a session that
 * has already been consumed by a prior rotation, this is treated as a
 * security event — every session for the user is revoked and
 * {@link RefreshReuseDetectedError} is thrown, forcing a full re-login.
 */
export async function rotateRefreshToken(
  refreshToken: string,
  deps: RefreshRotationDeps,
): Promise<RotateResult> {
  const payload = await deps.jwt.verifyRefreshToken(refreshToken);
  const jti = requireJti(payload);
  const userId = requireSub(payload);

  if (await deps.revocationStore.isRevoked(jti)) {
    throw new RevokedTokenError(`Refresh token "${jti}" has been revoked`);
  }

  const session = await deps.sessionStore.find(jti);
  if (!session) {
    throw new SessionExpiredError(`No active session found for refresh token "${jti}"`);
  }

  if (deps.reuseDetection && session.consumedAt != null) {
    await deps.hooks.onReuseDetected?.({ jti, userId });
    await deps.sessionStore.deleteByUser(userId);
    await deps.revocationStore.revoke({
      jti,
      expiresAt: session.expiresAt,
      reason: "reuse-detected",
    });
    throw new RefreshReuseDetectedError(
      `Refresh token "${jti}" was already used. All sessions for this user have been revoked.`,
    );
  }

  const newJti = randomUUID();
  const nowSeconds = Math.floor(Date.now() / 1000);
  const newExpiresAt = nowSeconds + deps.refreshTtlSeconds;

  const [accessToken, refreshTokenNext] = await Promise.all([
    deps.jwt.signAccessToken({ sub: userId }),
    deps.jwt.signRefreshToken({ sub: userId }, { jti: newJti }),
  ]);

  await deps.sessionStore.rotate(jti, {
    jti: newJti,
    userId,
    deviceId: session.deviceId,
    expiresAt: newExpiresAt,
  });

  await deps.hooks.onRefresh?.({ oldJti: jti, newJti, userId });

  return { accessToken, refreshToken: refreshTokenNext, payload };
}

function requireJti(payload: TokenPayload): string {
  if (!payload.jti) {
    throw new SessionExpiredError("Refresh token is missing a jti claim");
  }
  return payload.jti;
}

function requireSub(payload: TokenPayload): string {
  if (!payload.sub) {
    throw new SessionExpiredError("Refresh token is missing a sub claim");
  }
  return payload.sub;
}
