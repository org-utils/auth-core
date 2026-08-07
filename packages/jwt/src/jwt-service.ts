import type {
  SignOptions,
  SupportedAlgorithm,
  SigningKey,
  TokenPayload,
  VerifyOptions,
} from "@auth-core/shared";
import { ConfigurationError } from "@auth-core/shared";
import { KeyRing } from "./keys.js";
import { signToken as signTokenImpl } from "./sign.js";
import { decodeToken as decodeTokenImpl, verifyToken as verifyTokenImpl } from "./verify.js";

export interface JwtServiceOptions {
  keys: SigningKey[];
  /** kid to sign new tokens with. Defaults to the last key in `keys`. */
  currentKid?: string;
  /** Algorithms accepted during verification. Defaults to every algorithm present in `keys`. */
  allowedAlgorithms?: SupportedAlgorithm[];
  issuer?: string;
  audience?: string;
  clockToleranceSeconds?: number;
  accessTokenTtlSeconds?: number;
  refreshTokenTtlSeconds?: number;
}

const DEFAULT_ACCESS_TTL = 15 * 60; // 15 minutes
const DEFAULT_REFRESH_TTL = 30 * 24 * 60 * 60; // 30 days

export class JwtService {
  private readonly keyRing: KeyRing;
  private readonly allowedAlgorithms: SupportedAlgorithm[];
  private readonly issuer?: string;
  private readonly audience?: string;
  private readonly clockToleranceSeconds: number;
  private readonly accessTtl: number;
  private readonly refreshTtl: number;

  constructor(options: JwtServiceOptions) {
    if (!options.keys || options.keys.length === 0) {
      throw new ConfigurationError("JwtService requires at least one signing key");
    }
    this.keyRing = new KeyRing(options.keys, options.currentKid);
    this.allowedAlgorithms = options.allowedAlgorithms ?? [...new Set(options.keys.map((k) => k.algorithm))];
    this.issuer = options.issuer;
    this.audience = options.audience;
    this.clockToleranceSeconds = options.clockToleranceSeconds ?? 5;
    this.accessTtl = options.accessTokenTtlSeconds ?? DEFAULT_ACCESS_TTL;
    this.refreshTtl = options.refreshTokenTtlSeconds ?? DEFAULT_REFRESH_TTL;
  }

  /** Generic signer — works for any token type (access, refresh, password-reset, ...). */
  signToken(payload: TokenPayload, defaultExpirySeconds = this.accessTtl, options?: SignOptions): Promise<string> {
    const withIssuerAudience: TokenPayload = {
      ...payload,
      iss: payload.iss ?? this.issuer,
      aud: payload.aud ?? this.audience,
    };
    return signTokenImpl(this.keyRing, withIssuerAudience, defaultExpirySeconds, options);
  }

  /** Generic verifier — works for any token type. */
  verifyToken(token: string, options?: VerifyOptions): Promise<TokenPayload> {
    return verifyTokenImpl(
      this.keyRing,
      token,
      {
        allowedAlgorithms: this.allowedAlgorithms,
        clockToleranceSeconds: this.clockToleranceSeconds,
        issuer: this.issuer,
        audience: this.audience,
      },
      options,
    );
  }

  decodeToken(token: string): { header: Record<string, unknown>; payload: TokenPayload } {
    return decodeTokenImpl(token);
  }

  signAccessToken(payload: TokenPayload, options?: SignOptions): Promise<string> {
    return this.signToken({ ...payload, type: "access" }, this.accessTtl, options);
  }

  verifyAccessToken(token: string, options?: VerifyOptions): Promise<TokenPayload> {
    return this.verifyToken(token, {
      ...options,
      expectedClaims: { type: "access", ...options?.expectedClaims },
    });
  }

  signRefreshToken(payload: TokenPayload, options?: SignOptions): Promise<string> {
    return this.signToken({ ...payload, type: "refresh" }, this.refreshTtl, options);
  }

  verifyRefreshToken(token: string, options?: VerifyOptions): Promise<TokenPayload> {
    return this.verifyToken(token, {
      ...options,
      expectedClaims: { type: "refresh", ...options?.expectedClaims },
    });
  }

  /** Lists configured key ids — useful when publishing a JWKS for asymmetric algorithms. */
  get keyIds(): string[] {
    return this.keyRing.all().map((k) => k.kid);
  }
}
