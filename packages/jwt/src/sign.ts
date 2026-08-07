import { SignJWT } from "jose";
import { randomUUID } from "node:crypto";
import type { SignOptions, TokenPayload } from "@auth-core/shared";
import { ConfigurationError } from "@auth-core/shared";
import type { KeyRing } from "./keys.js";
import { resolveKeyMaterial } from "./keys.js";

function parseExpiry(value: number | string | undefined, fallbackSeconds: number): number {
  if (value == null) return fallbackSeconds;
  if (typeof value === "number") return value;
  // jose accepts human-readable strings ("15m", "30d") directly for setExpirationTime,
  // but we also support them here for a consistent numeric-seconds internal contract.
  const match = /^(\d+)\s*(s|m|h|d|w)$/i.exec(value.trim());
  if (!match) {
    throw new ConfigurationError(`Invalid expiresIn value: "${value}". Use seconds or "<n>[s|m|h|d|w]".`);
  }
  const n = Number(match[1]);
  const unit = match[2]!.toLowerCase();
  const multiplier = { s: 1, m: 60, h: 3600, d: 86_400, w: 604_800 }[unit]!;
  return n * multiplier;
}

export async function signToken(
  keyRing: KeyRing,
  payload: TokenPayload,
  defaultExpirySeconds: number,
  options: SignOptions = {},
): Promise<string> {
  const key = options.kid ? keyRing.byKid(options.kid) : keyRing.current;
  if (!key) {
    throw new ConfigurationError(`No signing key found for kid "${options.kid}"`);
  }

  const jti = options.jti ?? payload.jti ?? randomUUID();
  const expirySeconds = parseExpiry(options.expiresIn, defaultExpirySeconds);
  const nowSeconds = Math.floor(Date.now() / 1000);

  let builder = new SignJWT({ ...payload, jti: undefined })
    .setProtectedHeader({ alg: key.algorithm, kid: key.kid, ...(options.headers ?? {}) })
    .setIssuedAt(payload.iat ?? nowSeconds)
    .setExpirationTime(nowSeconds + expirySeconds)
    .setJti(jti);

  if (payload.iss) builder = builder.setIssuer(payload.iss);
  if (payload.aud) builder = builder.setAudience(payload.aud);
  if (payload.sub) builder = builder.setSubject(payload.sub);
  if (payload.nbf != null) builder = builder.setNotBefore(payload.nbf);

  const keyMaterial = resolveKeyMaterial(key, "privateKey");
  return builder.sign(keyMaterial as unknown as Uint8Array);
}
