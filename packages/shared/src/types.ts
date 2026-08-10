/** Well-known token "types" the library ships helpers for. Consumers may use any string. */
export type WellKnownTokenType =
  | "access"
  | "refresh"
  | "password-reset"
  | "email-verification"
  | "magic-link"
  | "invitation"
  | "api-key"
  | "service-token";

export type TokenType = WellKnownTokenType | (string & {});

/** Base registered claims (RFC 7519) plus the library's own `type` discriminator. */
export interface BaseClaims {
  /** Subject — typically the user id. */
  sub?: string;
  /** Issuer. */
  iss?: string;
  /** Audience. */
  aud?: string | string[];
  /** Expiration time (seconds since epoch). Set automatically. */
  exp?: number;
  /** Issued-at time (seconds since epoch). Set automatically. */
  iat?: number;
  /** Not-before time (seconds since epoch). */
  nbf?: number;
  /** JWT ID — unique per token. Set automatically unless overridden. */
  jti?: string;
  /** Discriminator used by signToken/verifyToken's expectedClaims.type check. */
  type?: TokenType;
  /** Free-form sub-classification, e.g. "purpose": "password-reset". */
  purpose?: string;
}

/** A JWT payload is the base claims plus arbitrary custom claims. */
export type TokenPayload<TCustom extends Record<string, unknown> = Record<string, unknown>> =
  BaseClaims & TCustom;

export type SupportedAlgorithm =
  | "HS256"
  | "HS384"
  | "HS512"
  | "RS256"
  | "RS384"
  | "RS512"
  | "ES256"
  | "ES384"
  | "ES512"
  | "EdDSA";

/** A signing key — either a raw symmetric secret or an asymmetric key pair reference. */
export interface SigningKey {
  /** Key id, embedded in the JWT header as `kid`. Required for rotation. */
  kid: string;
  algorithm: SupportedAlgorithm;
  /** For HS-family algorithms: the shared secret. For RS/ES/EdDSA algorithms: the private key (PEM, JWK, or KeyObject). */
  privateKey: unknown;
  /** For RS/ES/EdDSA algorithms: the public key used for verification. Omit for symmetric algorithms. */
  publicKey?: unknown;
}

export interface ExpectedClaims {
  type?: TokenType;
  purpose?: string;
  iss?: string;
  aud?: string;
  sub?: string;
  [customClaim: string]: unknown;
}

export interface VerifyOptions {
  expectedClaims?: ExpectedClaims;
  /** Clock skew tolerance, in seconds. Defaults to the configured global value. */
  clockToleranceSeconds?: number;
  /** Explicit algorithm allow-list for this verification call. */
  algorithms?: SupportedAlgorithm[];
}

export interface SignOptions {
  /** Overrides the default expiration (seconds, or a human string like "15m"). */
  expiresIn?: number | string;
  /** Explicit key id to sign with, for multi-key rotation setups. */
  kid?: string;
  /** Additional (non-registered) JWT header fields. */
  headers?: Record<string, unknown>;
  /** Explicit jti. If omitted one is generated with crypto.randomUUID(). */
  jti?: string;
}

/* ---------------------------------------------------------------------- */
/* Revocation                                                              */
/* ---------------------------------------------------------------------- */

export interface RevocationRecord {
  jti: string;
  /** Unix seconds after which this revocation entry may be garbage collected. */
  expiresAt: number;
  reason?: "logout" | "logout-all" | "password-change" | "admin-revocation" | "reuse-detected" | (string & {});
}

/**
 * Storage-agnostic interface for tracking revoked token ids (jti).
 * Implementations MUST auto-expire entries at/after `expiresAt` so the
 * store doesn't grow unbounded (e.g. Redis TTL, or a sweep in-memory).
 */
export interface RevocationStore {
  revoke(record: RevocationRecord): Promise<void>;
  revokeMany(records: RevocationRecord[]): Promise<void>;
  isRevoked(jti: string): Promise<boolean>;
}

/* ---------------------------------------------------------------------- */
/* Sessions                                                                 */
/* ---------------------------------------------------------------------- */

export interface SessionRecord {
  jti: string;
  userId: string;
  deviceId?: string;
  createdAt: number;
  expiresAt: number;
  /** Parent jti this session was rotated from, for reuse-detection chains. */
  rotatedFrom?: string;
  /** Set once this session's refresh token has been consumed by a rotation. */
  consumedAt?: number;
}

export interface CreateSessionInput {
  jti: string;
  userId: string;
  deviceId?: string;
  expiresAt: number;
}

export interface UpdateSessionInput {
  expiresAt?: number;
  consumedAt?: number;
}

/**
 * Storage-agnostic interface for the refresh-token session table.
 * Implementations must NEVER persist raw access or refresh tokens —
 * only metadata (jti, userId, deviceId, timestamps).
 */
export interface SessionStore {
  create(input: CreateSessionInput): Promise<SessionRecord>;
  update(jti: string, patch: UpdateSessionInput, userId?: string): Promise<SessionRecord | null>;
  /** Atomically marks `jti` as rotated and creates the successor session. */
  rotate(jti: string, next: CreateSessionInput, userId?: string): Promise<SessionRecord>;
  delete(jti: string, userId?: string): Promise<void>;
  /** Deletes every session belonging to a user (used by logoutAll). */
  deleteByUser(userId: string): Promise<void>;
  find(jti: string, userId?: string): Promise<SessionRecord | null>;
}

/* ---------------------------------------------------------------------- */
/* Hooks                                                                    */
/* ---------------------------------------------------------------------- */

export interface AuthHooks {
  onTokenIssued?(info: { type: TokenType; jti: string; sub?: string; deviceId?: string }): void | Promise<void>
  onTokensIssued?(info: { type: TokenType; jti: string; sub?: string; deviceId?: string }[]): void | Promise<void>;
  onTokenVerified?(info: { type: TokenType; jti: string; sub?: string }): void | Promise<void>;
  onTokenRevoked?(info: { jti: string; reason?: string }): void | Promise<void>;
  onRefresh?(info: { oldJti: string; newJti: string; userId: string, deviceId?: string }): void | Promise<void>;
  onReuseDetected?(info: { jti: string; userId: string }): void | Promise<void>;
  onSessionCreated?(info: SessionRecord): void | Promise<void>;
  onSessionDeleted?(info: { jti: string; userId: string }): void | Promise<void>;
}
