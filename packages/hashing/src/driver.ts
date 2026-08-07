/**
 * A hashing driver wraps a single algorithm (argon2, bcrypt, ...) behind a
 * uniform interface so {@link PasswordService} can support multiple
 * algorithms side-by-side (e.g. during a migration) and so new algorithms
 * can be added without changing the public API.
 */
export interface HashingDriver {
  /** Stable name embedded implicitly in the hash string, used for routing verify() calls. */
  readonly name: string;

  hash(password: string): Promise<string>;

  verify(password: string, hash: string): Promise<boolean>;

  /** Returns true if `hash` was produced with weaker-than-current parameters and should be regenerated. */
  needsRehash(hash: string): boolean;

  /** Returns true if this driver produced the given hash (used to route verify() across multiple drivers). */
  recognizes(hash: string): boolean;
}
