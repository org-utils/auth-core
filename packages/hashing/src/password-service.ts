import { HashVerificationError, ConfigurationError } from "@auth-core/shared";
import type { HashingDriver } from "./driver.js";
import { assertPasswordStrength, type PasswordPolicy } from "./password-strength.js";

export interface PasswordServiceOptions {
  /** The driver used for hashing new passwords. */
  driver: HashingDriver;
  /**
   * Additional drivers this service can still *verify* (but never hashes
   * with), so you can safely migrate away from an old algorithm: pass the
   * old driver here, and every login using it will be transparently
   * rehashed to `driver` on next verify (see {@link PasswordService.verify}).
   */
  legacyDrivers?: HashingDriver[];
  policy?: PasswordPolicy;
}

export interface VerifyResult {
  valid: boolean;
  /** True if the stored hash should be replaced with a fresh one from the primary driver. */
  needsRehash: boolean;
}

export class PasswordService {
  private readonly driver: HashingDriver;
  private readonly legacyDrivers: HashingDriver[];
  private readonly policy: PasswordPolicy;

  constructor(options: PasswordServiceOptions) {
    if (!options.driver) {
      throw new ConfigurationError("PasswordService requires a primary hashing driver");
    }
    this.driver = options.driver;
    this.legacyDrivers = options.legacyDrivers ?? [];
    this.policy = options.policy ?? {};
  }

  /** Validates password strength, then hashes it with the primary driver. */
  async hash(password: string, policyOverride?: PasswordPolicy): Promise<string> {
    assertPasswordStrength(password, policyOverride ?? this.policy);
    return this.driver.hash(password);
  }

  /**
   * Verifies a password against a stored hash, routing to whichever driver
   * (primary or legacy) produced the hash. Returns `needsRehash: true` when
   * the hash was produced by a legacy driver or with outdated parameters,
   * so callers can transparently re-hash and persist the upgraded value.
   */
  async verify(password: string, hash: string): Promise<VerifyResult> {
    const driver = this.resolveDriver(hash);
    if (!driver) {
      throw new HashVerificationError("Hash was not produced by any configured hashing driver");
    }

    const valid = await driver.verify(password, hash);
    if (!valid) return { valid: false, needsRehash: false };

    const outdatedDriver = driver.name !== this.driver.name;
    return { valid: true, needsRehash: outdatedDriver || this.driver.needsRehash(hash) };
  }

  /** Standalone needsRehash check, e.g. for periodic maintenance jobs. */
  needsRehash(hash: string): boolean {
    const driver = this.resolveDriver(hash);
    if (!driver) return true;
    return driver.name !== this.driver.name || this.driver.needsRehash(hash);
  }

  private resolveDriver(hash: string): HashingDriver | undefined {
    if (this.driver.recognizes(hash)) return this.driver;
    return this.legacyDrivers.find((d) => d.recognizes(hash));
  }
}
