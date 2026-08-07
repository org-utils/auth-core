import bcrypt from "bcrypt";
import type { HashingDriver } from "../driver.js";

export interface BcryptDriverOptions {
  /** Cost factor (rounds). Default: 12. */
  cost?: number;
  pepper?: string;
}

const BCRYPT_HASH_RE = /^\$2[aby]?\$\d{2}\$/;

export function createBcryptDriver(options: BcryptDriverOptions = {}): HashingDriver {
  const cost = options.cost ?? 12;
  const pepper = options.pepper ?? "";

  return {
    name: "bcrypt",

    async hash(password: string): Promise<string> {
      return bcrypt.hash(password + pepper, cost);
    },

    async verify(password: string, hash: string): Promise<boolean> {
      try {
        return await bcrypt.compare(password + pepper, hash);
      } catch {
        return false;
      }
    },

    needsRehash(hash: string): boolean {
      const match = BCRYPT_HASH_RE.exec(hash);
      if (!match) return true;
      const rounds = Number(hash.slice(4, 6));
      return rounds !== cost;
    },

    recognizes(hash: string): boolean {
      return BCRYPT_HASH_RE.test(hash);
    },
  };
}
