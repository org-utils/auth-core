import { JwtService } from "@auth-core/jwt";
import { PasswordService } from "@auth-core/hashing";
import type { SessionRecord, SignOptions, TokenPayload, VerifyOptions } from "@auth-core/shared";
import { RevokedTokenError, uniqueId } from "@auth-core/shared";
import type { AuthConfig } from "./config.js";
import { resolveAuthConfig } from "./config.js";
import { rotateRefreshToken as rotaterefreshToken, type RotateResult } from "./refresh-rotation.js";

export interface LoginSessionInput {
  userId: string;
  deviceId?: string;
}

export interface LoginResult {
  accessToken: string;
  refreshToken: string;
  accessJti?: string;
  refreshJti?: string;
}

export class Auth {
  readonly jwt: JwtService;
  readonly password: PasswordService;
  private readonly config: ReturnType<typeof resolveAuthConfig>;

  constructor(config: AuthConfig) {
    this.config = resolveAuthConfig(config);
    this.jwt = new JwtService({
      keys: this.config.jwt.keys,
      currentKid: this.config.jwt.currentKid,
      allowedAlgorithms: this.config.jwt.allowedAlgorithms,
      issuer: this.config.jwt.issuer,
      audience: this.config.jwt.audience,
      clockToleranceSeconds: this.config.jwt.clockToleranceSeconds,
      accessTokenTtlSeconds: this.config.tokens.access.ttlSeconds,
      refreshTokenTtlSeconds: this.config.tokens.refresh.ttlSeconds,
    });
    this.password = new PasswordService({
      driver: this.config.hashing.driver,
      legacyDrivers: this.config.hashing.legacyDrivers,
      policy: this.config.hashing.policy,
    });
  }

  /* ---------------------------- Passwords ---------------------------- */

  hashPassword(password: string): Promise<string> {
    return this.password.hash(password);
  }

  async verifyPassword(password: string, hash: string): Promise<boolean> {
    const result = await this.password.verify(password, hash);
    return result.valid;
  }

  /* ------------------------------ JWTs -------------------------------- */

  signToken(payload: TokenPayload, options?: SignOptions): Promise<string> {
    return this.jwt.signToken(payload, this.config.tokens.access.ttlSeconds, options);
  }

  async verifyToken(token: string, options?: VerifyOptions): Promise<TokenPayload> {
    const payload = await this.jwt.verifyToken(token, options);
    await this.assertNotRevoked(payload);
    await this.config.hooks.onTokenVerified?.({
      type: payload.type ?? "unknown",
      jti: payload.jti ?? "",
      sub: payload.sub,
    });
    return payload;
  }

  signAccessToken(payload: TokenPayload, options?: SignOptions): Promise<string> {
    return this.jwt.signAccessToken(payload, options);
  }

  async verifyAccessToken(token: string, options?: VerifyOptions): Promise<TokenPayload> {
    const payload = await this.jwt.verifyAccessToken(token, options);
    await this.assertNotRevoked(payload);
    return payload;
  }

  signRefreshToken(payload: TokenPayload, options?: SignOptions): Promise<string> {
    return this.jwt.signRefreshToken(payload, options);
  }

  async verifyRefreshToken(token: string, options?: VerifyOptions): Promise<TokenPayload> {
    const payload = await this.jwt.verifyRefreshToken(token, options);
    await this.assertNotRevoked(payload);
    return payload;
  }

  /* --------------------------- Sessions -------------------------------- */

  /** Issues an access/refresh token pair and creates the backing session record. Call this on login. */
  async login(input: LoginSessionInput): Promise<LoginResult> {
    const accessJti = uniqueId();
    const refreshJti = uniqueId();
    const nowSeconds = Math.floor(Date.now() / 1000);
    const expiresAt = nowSeconds + this.config.tokens.refresh.ttlSeconds;
    const {userId, deviceId} = input;
    const [accessToken, refreshToken] = await Promise.all([
      this.jwt.signAccessToken({ sub: userId }, { jti: accessJti }),
      this.jwt.signRefreshToken({ sub: userId }, { jti: refreshJti }),
    ]);

    const session = await this.config.stores.session.create({
      jti: refreshJti,
      userId: userId,
      deviceId: deviceId,
      expiresAt,
    });
    await this.config.hooks.onSessionCreated?.(session);
    // await this.config.hooks.onTokenIssued?.({ type: "refresh", jti: refreshJti, sub: userId, deviceId });
    await this.config.hooks.onTokensIssued?.([{ type: "access", jti: accessJti, sub: userId, deviceId },
    { type: "refresh", jti: refreshJti, sub: userId, deviceId }]);

    return { accessToken, refreshToken, accessJti, refreshJti };
  }

  async rotateRefreshToken(refreshToken: string): Promise<RotateResult> {
    return rotaterefreshToken(refreshToken, {
      jwt: this.jwt,
      sessionStore: this.config.stores.session,
      revocationStore: this.config.stores.revocation,
      hooks: this.config.hooks,
      accessTtlSeconds: this.config.tokens.access.ttlSeconds,
      refreshTtlSeconds: this.config.tokens.refresh.ttlSeconds,
      reuseDetection: this.config.session.reuseDetection,
    });
  }

  /* --------------------------- Revocation ------------------------------ */

  /** Revokes a single token by jti (does not require knowing the token type). */
  async revokeToken(jti: string, expiresAt: number, reason: string = "admin-revocation"): Promise<void> {
    await this.config.stores.revocation.revoke({ jti, expiresAt, reason });
    await this.config.hooks.onTokenRevoked?.({ jti, reason });
  }

  /** Revokes every session for a user (e.g. on account compromise or password change). */
  async revokeUser(userId: string, reason: string = "admin-revocation"): Promise<void> {
    await this.config.stores.session.deleteByUser(userId);
    await this.config.hooks.onSessionDeleted?.({ jti: "*", userId });
    void reason;
  }

  /** Logs out a single session (device). */
  async logout(sessionJti: string): Promise<void> {
    const session = await this.getSession(sessionJti);
    await this.deleteSession(sessionJti);
    if (session) {
      await this.config.stores.revocation.revoke({
        jti: sessionJti,
        expiresAt: session.expiresAt,
        reason: "logout",
      });
      await this.config.hooks.onSessionDeleted?.({ jti: sessionJti, userId: session.userId });
    }
  }

  /** Logs out every device/session for a user. */
  async logoutAll(userId: string): Promise<void> {
    await this.config.stores.session.deleteByUser(userId);
    await this.config.hooks.onSessionDeleted?.({ jti: "*", userId });
  }

  private async assertNotRevoked(payload: TokenPayload): Promise<void> {
    if (!payload.jti) return;
    if (await this.config.stores.revocation.isRevoked(payload.jti)) {
      throw new RevokedTokenError(`Token "${payload.jti}" has been revoked`);
    }
  }
  /**
   *
   * @param sessionJti
   * @returns @type {SessionRecord | null}
   */
  async getSession(sessionJti: string): Promise<SessionRecord | null> {
    const session = await this.config.stores.session.find(sessionJti);
    return session;
  }
  /**
   *
   * @param sessionJti
   */
  async deleteSession(sessionJti: string): Promise<void> {
    await this.config.stores.session.delete(sessionJti);
  }

  /**
   * Update a session's data.
   * @param sessionJti
   * @param data
   */
  async updateSession(sessionJti: string, data: Partial<SessionRecord>): Promise<SessionRecord | null> {
    return await this.config.stores.session.update(sessionJti, data);
  }
}

/** Creates a fully-wired Auth instance from a validated {@link AuthConfig}. */
export function createAuth(config: AuthConfig): Auth {
  return new Auth(config);
}
