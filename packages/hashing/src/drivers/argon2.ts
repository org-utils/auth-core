import * as argon2 from "argon2";
import type { HashingDriver } from "../driver.js";

export interface Argon2DriverOptions {
  /** Memory cost in KiB. Default: 19456 (~19 MiB), OWASP-recommended minimum. */
  memoryCost?: number;
  /** Time cost (iterations). Default: 2. */
  timeCost?: number;
  /** Degree of parallelism. Default: 1. */
  parallelism?: number;
  /** Secret value ("pepper") mixed into every hash, held outside the DB (e.g. in a KMS/env var). */
  pepper?: string;
}

const DEFAULTS: Required<Omit<Argon2DriverOptions, "pepper">> = {
  memoryCost: 19_456,
  timeCost: 2,
  parallelism: 1,
};

export function createArgon2Driver(options: Argon2DriverOptions = {}): HashingDriver {
  const opts = { ...DEFAULTS, ...options };
  const secret = opts.pepper ? Buffer.from(opts.pepper, "utf8") : undefined;

  return {
    name: "argon2",

    async hash(password: string): Promise<string> {
      return argon2.hash(password, {
        type: argon2.argon2id,
        memoryCost: opts.memoryCost,
        timeCost: opts.timeCost,
        parallelism: opts.parallelism,
        secret,
      });
    },

    async verify(password: string, hash: string): Promise<boolean> {
      try {
        return await argon2.verify(hash, password, { secret });
      } catch {
        // Malformed hash, wrong driver, etc. Treat as a verification failure,
        // never leak internal errors to the caller.
        return false;
      }
    },

    needsRehash(hash: string): boolean {
      try {
        return argon2.needsRehash(hash, {
          memoryCost: opts.memoryCost,
          timeCost: opts.timeCost,
          parallelism: opts.parallelism,
        });
      } catch {
        return true;
      }
    },

    recognizes(hash: string): boolean {
      return hash.startsWith("$argon2id$") || hash.startsWith("$argon2i$") || hash.startsWith("$argon2d$");
    },
  };
}
