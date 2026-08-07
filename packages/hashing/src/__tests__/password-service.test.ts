import { describe, expect, it } from "vitest";
import { HashVerificationError, WeakPasswordError } from "@auth-core/shared";
import { PasswordService } from "../password-service.js";
import { createArgon2Driver } from "../drivers/argon2.js";
import { createBcryptDriver } from "../drivers/bcrypt.js";

describe("PasswordService", () => {
  it("hashes and verifies a password with argon2", async () => {
    const service = new PasswordService({ driver: createArgon2Driver() });
    const hash = await service.hash("CorrectHorse1");
    expect(hash).toMatch(/^\$argon2id\$/);
    const result = await service.verify("CorrectHorse1", hash);
    expect(result.valid).toBe(true);
    expect(result.needsRehash).toBe(false);
  });

  it("rejects an incorrect password", async () => {
    const service = new PasswordService({ driver: createArgon2Driver() });
    const hash = await service.hash("CorrectHorse1");
    const result = await service.verify("WrongPassword1", hash);
    expect(result.valid).toBe(false);
  });

  it("enforces the strength policy on hash()", async () => {
    const service = new PasswordService({ driver: createArgon2Driver() });
    await expect(service.hash("weak")).rejects.toBeInstanceOf(WeakPasswordError);
  });

  it("flags legacy-driver hashes as needing rehash even when the password is correct", async () => {
    const legacy = createBcryptDriver({ cost: 4 });
    const current = createArgon2Driver();
    const service = new PasswordService({ driver: current, legacyDrivers: [legacy] });

    const oldHash = await legacy.hash("MigrateMe1");
    const result = await service.verify("MigrateMe1", oldHash);
    expect(result.valid).toBe(true);
    expect(result.needsRehash).toBe(true);
  });

  it("throws HashVerificationError for a hash no configured driver recognizes", async () => {
    const service = new PasswordService({ driver: createArgon2Driver() });
    await expect(service.verify("x", "not-a-real-hash")).rejects.toBeInstanceOf(HashVerificationError);
  });

  it("flags outdated argon2 parameters as needing rehash", async () => {
    const weakParams = createArgon2Driver({ memoryCost: 8192, timeCost: 2 });
    const strongParams = createArgon2Driver({ memoryCost: 19456, timeCost: 3 });
    const service = new PasswordService({ driver: strongParams });

    const oldHash = await weakParams.hash("SomePassword1");
    const result = await service.verify("SomePassword1", oldHash);
    expect(result.valid).toBe(true);
    expect(result.needsRehash).toBe(true);
  });
});
