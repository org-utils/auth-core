import { WeakPasswordError } from "@auth-core/shared";

export interface PasswordPolicy {
  minLength?: number;
  maxLength?: number;
  requireUppercase?: boolean;
  requireLowercase?: boolean;
  requireNumber?: boolean;
  requireSymbol?: boolean;
  /** Reject passwords found in this deny-list (e.g. common passwords, breach lists). */
  denyList?: Iterable<string> | Set<string>;
}

export const DEFAULT_PASSWORD_POLICY: Required<Omit<PasswordPolicy, "denyList">> & {
  denyList?: PasswordPolicy["denyList"];
} = {
  minLength: 8,
  maxLength: 128,
  requireUppercase: true,
  requireLowercase: true,
  requireNumber: true,
  requireSymbol: false,
  denyList: undefined,
};

const SYMBOL_RE = /[!"#$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~]/;

/**
 * Validates a password against a configurable strength policy.
 * Throws {@link WeakPasswordError} listing every failed rule if invalid.
 */
export function assertPasswordStrength(password: string, policy: PasswordPolicy = {}): void {
  const p = { ...DEFAULT_PASSWORD_POLICY, ...policy };
  const failed: string[] = [];

  if (password.length < p.minLength) failed.push(`minLength:${p.minLength}`);
  if (password.length > p.maxLength) failed.push(`maxLength:${p.maxLength}`);
  if (p.requireUppercase && !/[A-Z]/.test(password)) failed.push("requireUppercase");
  if (p.requireLowercase && !/[a-z]/.test(password)) failed.push("requireLowercase");
  if (p.requireNumber && !/[0-9]/.test(password)) failed.push("requireNumber");
  if (p.requireSymbol && !SYMBOL_RE.test(password)) failed.push("requireSymbol");

  if (p.denyList) {
    const denySet = p.denyList instanceof Set ? p.denyList : new Set(p.denyList);
    if (denySet.has(password.toLowerCase())) failed.push("denyList");
  }

  if (failed.length > 0) {
    throw new WeakPasswordError(
      `Password does not satisfy the configured strength policy: ${failed.join(", ")}`,
      failed,
    );
  }
}
