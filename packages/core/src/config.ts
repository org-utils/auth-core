import { z } from "zod";
import type {
  AuthHooks,
  RevocationStore,
  SessionStore,
  SigningKey,
  SupportedAlgorithm,
} from "@auth-core/shared";
import { ConfigurationError } from "@auth-core/shared";
import type { HashingDriver } from "@auth-core/hashing";
import type { PasswordPolicy } from "@auth-core/hashing";

/* ---------------------------------------------------------------------- */
/* Zod schema — validates the *primitive* configuration shape only.        */
/* Injected instances (drivers/stores/keys) are validated structurally     */
/* by TypeScript, not by zod, per the "don't use zod for app payloads"     */
/* and "core has no infra knowledge" design constraints.                   */
/* ---------------------------------------------------------------------- */

const passwordPolicySchema = z
  .object({
    minLength: z.number().int().positive().optional(),
    maxLength: z.number().int().positive().optional(),
    requireUppercase: z.boolean().optional(),
    requireLowercase: z.boolean().optional(),
    requireNumber: z.boolean().optional(),
    requireSymbol: z.boolean().optional(),
  })
  .strict()
  .optional();

const tokenTtlSchema = z
  .object({
    ttlSeconds: z.number().int().positive().optional(),
  })
  .strict()
  .optional();

export const authConfigSchema = z
  .object({
    hashing: z
      .object({
        policy: passwordPolicySchema,
      })
      .strict()
      .optional(),
    jwt: z
      .object({
        currentKid: z.string().min(1).optional(),
        allowedAlgorithms: z.array(z.string()).optional(),
        issuer: z.string().min(1).optional(),
        audience: z.string().min(1).optional(),
        clockToleranceSeconds: z.number().int().nonnegative().optional(),
      })
      .strict()
      .optional(),
    tokens: z
      .object({
        access: tokenTtlSchema,
        refresh: tokenTtlSchema,
      })
      .strict()
      .optional(),
    session: z
      .object({
        rotateOnRefresh: z.boolean().optional(),
        reuseDetection: z.boolean().optional(),
      })
      .strict()
      .optional(),
  })
  .strict();

export type ValidatedAuthConfigShape = z.infer<typeof authConfigSchema>;

/* ---------------------------------------------------------------------- */
/* Full config, including injected instances.                              */
/* ---------------------------------------------------------------------- */

export interface AuthConfig {
  hashing: {
    driver: HashingDriver;
    legacyDrivers?: HashingDriver[];
    policy?: PasswordPolicy;
  };
  jwt: {
    keys: SigningKey[];
    currentKid?: string;
    allowedAlgorithms?: SupportedAlgorithm[];
    issuer?: string;
    audience?: string;
    clockToleranceSeconds?: number;
  };
  tokens?: {
    access?: { ttlSeconds?: number };
    refresh?: { ttlSeconds?: number };
  };
  session?: {
    /** Issue a fresh refresh token on every access-token refresh. Default: true. */
    rotateOnRefresh?: boolean;
    /** Detect reuse of an already-rotated refresh token and treat it as a security event. Default: true. */
    reuseDetection?: boolean;
  };
  stores: {
    revocation: RevocationStore;
    session: SessionStore;
  };
  hooks?: AuthHooks;
}

export interface ResolvedAuthConfig extends Required<Pick<AuthConfig, "hashing" | "jwt" | "stores">> {
  tokens: { access: { ttlSeconds: number }; refresh: { ttlSeconds: number } };
  session: { rotateOnRefresh: boolean; reuseDetection: boolean };
  hooks: AuthHooks;
}

const DEFAULT_ACCESS_TTL_SECONDS = 15 * 60;
const DEFAULT_REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60;

/**
 * Validates the primitive portion of an {@link AuthConfig} with zod, checks
 * required injected dependencies are present, and fills in defaults.
 * Throws {@link ConfigurationError} on any problem.
 */
export function resolveAuthConfig(config: AuthConfig): ResolvedAuthConfig {
  const primitiveSlice = {
    hashing: config.hashing ? { policy: config.hashing.policy } : undefined,
    jwt: config.jwt
      ? {
          currentKid: config.jwt.currentKid,
          allowedAlgorithms: config.jwt.allowedAlgorithms,
          issuer: config.jwt.issuer,
          audience: config.jwt.audience,
          clockToleranceSeconds: config.jwt.clockToleranceSeconds,
        }
      : undefined,
    tokens: config.tokens,
    session: config.session,
  };

  const parsed = authConfigSchema.safeParse(primitiveSlice);
  if (!parsed.success) {
    throw new ConfigurationError(`Invalid auth-core configuration: ${parsed.error.message}`);
  }

  if (!config.hashing?.driver) {
    throw new ConfigurationError("config.hashing.driver is required");
  }
  if (!config.jwt?.keys || config.jwt.keys.length === 0) {
    throw new ConfigurationError("config.jwt.keys must contain at least one signing key");
  }
  if (!config.stores?.revocation) {
    throw new ConfigurationError("config.stores.revocation is required");
  }
  if (!config.stores?.session) {
    throw new ConfigurationError("config.stores.session is required");
  }

  return {
    hashing: config.hashing,
    jwt: config.jwt,
    tokens: {
      access: { ttlSeconds: config.tokens?.access?.ttlSeconds ?? DEFAULT_ACCESS_TTL_SECONDS },
      refresh: { ttlSeconds: config.tokens?.refresh?.ttlSeconds ?? DEFAULT_REFRESH_TTL_SECONDS },
    },
    session: {
      rotateOnRefresh: config.session?.rotateOnRefresh ?? true,
      reuseDetection: config.session?.reuseDetection ?? true,
    },
    stores: config.stores,
    hooks: config.hooks ?? {},
  };
}
