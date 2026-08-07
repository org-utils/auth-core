/**
 * Base class for every error thrown by the authentication core.
 *
 * All auth-core errors extend this class so consumers can do a single
 * `instanceof AuthError` check, while still being able to narrow to a
 * specific error type when they need finer-grained handling.
 */
export abstract class AuthError extends Error {
  /** Stable machine-readable error code, safe to expose in logs/metrics. */
  abstract readonly code: string;

  /** HTTP status code a framework adapter would typically map this to. */
  abstract readonly httpStatus: number;

  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = new.target.name;
    Error.captureStackTrace?.(this, new.target);
  }
}

/** Token is malformed, has an unexpected shape, or fails schema checks. */
export class InvalidTokenError extends AuthError {
  readonly code = "AUTH_INVALID_TOKEN";
  readonly httpStatus = 401;
}

/** Token's `exp` claim is in the past. */
export class ExpiredTokenError extends AuthError {
  readonly code = "AUTH_EXPIRED_TOKEN";
  readonly httpStatus = 401;
}

/** Token signature could not be verified against the configured key(s). */
export class InvalidSignatureError extends AuthError {
  readonly code = "AUTH_INVALID_SIGNATURE";
  readonly httpStatus = 401;
}

/** Token uses an algorithm that is not in the configured allow-list. */
export class InvalidAlgorithmError extends AuthError {
  readonly code = "AUTH_INVALID_ALGORITHM";
  readonly httpStatus = 401;
}

/** Token's `jti` has been explicitly revoked. */
export class RevokedTokenError extends AuthError {
  readonly code = "AUTH_REVOKED_TOKEN";
  readonly httpStatus = 401;
}

/** Session referenced by a token no longer exists or has expired. */
export class SessionExpiredError extends AuthError {
  readonly code = "AUTH_SESSION_EXPIRED";
  readonly httpStatus = 401;
}

/**
 * A refresh token that was already rotated (consumed) has been presented
 * again. This is a strong signal of token theft; callers should treat this
 * as a security event and typically revoke the entire session family.
 */
export class RefreshReuseDetectedError extends AuthError {
  readonly code = "AUTH_REFRESH_REUSE_DETECTED";
  readonly httpStatus = 401;
}

/** Password does not satisfy the configured strength policy. */
export class WeakPasswordError extends AuthError {
  readonly code = "AUTH_WEAK_PASSWORD";
  readonly httpStatus = 400;

  constructor(
    message: string,
    public readonly failedRules: string[],
    options?: { cause?: unknown },
  ) {
    super(message, options);
  }
}

/** Password did not match the stored hash. */
export class HashVerificationError extends AuthError {
  readonly code = "AUTH_HASH_VERIFICATION_FAILED";
  readonly httpStatus = 401;
}

/** Library was misconfigured (invalid config shape, missing keys, etc). */
export class ConfigurationError extends AuthError {
  readonly code = "AUTH_CONFIGURATION_ERROR";
  readonly httpStatus = 500;
}

/** Token claim validation failed (iss/aud/sub/nbf/expected claims/etc). */
export class ClaimValidationError extends AuthError {
  readonly code = "AUTH_CLAIM_VALIDATION_FAILED";
  readonly httpStatus = 401;

  constructor(
    message: string,
    public readonly claim: string,
    options?: { cause?: unknown },
  ) {
    super(message, options);
  }
}
