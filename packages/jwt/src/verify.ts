import { jwtVerify, errors as joseErrors } from "jose";
import type { TokenPayload, VerifyOptions, SupportedAlgorithm } from "@auth-core/shared";
import {
  ExpiredTokenError,
  InvalidSignatureError,
  InvalidTokenError,
  InvalidAlgorithmError,
  ClaimValidationError,
} from "@auth-core/shared";
import type { KeyRing } from "./keys.js";
import { resolveKeyMaterial } from "./keys.js";

export interface VerifyTokenConfig {
  allowedAlgorithms: SupportedAlgorithm[];
  clockToleranceSeconds: number;
  issuer?: string;
  audience?: string;
}

export async function verifyToken(
  keyRing: KeyRing,
  token: string,
  config: VerifyTokenConfig,
  options: VerifyOptions = {},
): Promise<TokenPayload> {
  const algorithms = options.algorithms ?? config.allowedAlgorithms;
  const clockTolerance = options.clockToleranceSeconds ?? config.clockToleranceSeconds;

  let result;
  try {
    result = await jwtVerify(
      token,
      async (header) => {
        const key = header.kid ? keyRing.byKid(header.kid) : keyRing.current;
        if (!key) {
          throw new InvalidSignatureError(`No key found for kid "${header.kid ?? "(none)"}"`);
        }
        if (!algorithms.includes(key.algorithm)) {
          throw new InvalidAlgorithmError(`Algorithm "${key.algorithm}" is not in the allowed list`);
        }
        return resolveKeyMaterial(key, "publicKey" in key && key.publicKey ? "publicKey" : "privateKey") as unknown as Uint8Array;
      },
      {
        algorithms,
        clockTolerance,
        issuer: config.issuer,
        audience: config.audience,
      },
    );
  } catch (err) {
    if (err instanceof InvalidSignatureError || err instanceof InvalidAlgorithmError) throw err;
    if (err instanceof joseErrors.JWTExpired) {
      throw new ExpiredTokenError("Token has expired", { cause: err });
    }
    if (err instanceof joseErrors.JWTClaimValidationFailed) {
      throw new ClaimValidationError(`Claim validation failed: ${err.claim}`, err.claim, { cause: err });
    }
    if (err instanceof joseErrors.JWSSignatureVerificationFailed) {
      throw new InvalidSignatureError("Signature verification failed", { cause: err });
    }
    throw new InvalidTokenError("Token is malformed or invalid", { cause: err });
  }

  const payload = result.payload as TokenPayload;

  const expected = options.expectedClaims;
  if (expected) {
    for (const [claim, value] of Object.entries(expected)) {
      const actual = (payload as Record<string, unknown>)[claim];
      if (actual !== value) {
        throw new ClaimValidationError(
          `Expected claim "${claim}" to equal "${String(value)}", got "${String(actual)}"`,
          claim,
        );
      }
    }
  }

  return payload;
}

export function decodeToken(token: string): { header: Record<string, unknown>; payload: TokenPayload } {
  // Unverified decode — for inspection/debugging only, never trust this for authz decisions.
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new InvalidTokenError("Token does not have the expected header.payload.signature shape");
  }
  try {
    const header = JSON.parse(Buffer.from(parts[0]!, "base64url").toString("utf8"));
    const payload = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8"));
    return { header, payload };
  } catch (err) {
    throw new InvalidTokenError("Failed to decode token", { cause: err });
  }
}
