import { describe, expect, it } from "vitest";
import { assertPasswordStrength } from "../password-strength.js";
import { WeakPasswordError } from "@auth-core/shared";

describe("assertPasswordStrength", () => {
  it("accepts a password meeting the default policy", () => {
    expect(() => assertPasswordStrength("GoodPass1")).not.toThrow();
  });

  it("rejects passwords shorter than minLength", () => {
    expect(() => assertPasswordStrength("Ab1")).toThrow(WeakPasswordError);
  });

  it("rejects passwords missing an uppercase letter", () => {
    try {
      assertPasswordStrength("lowercase1");
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(WeakPasswordError);
      expect((err as WeakPasswordError).failedRules).toContain("requireUppercase");
    }
  });

  it("rejects passwords missing a number", () => {
    expect(() => assertPasswordStrength("NoNumberHere")).toThrow(WeakPasswordError);
  });

  it("respects a custom policy that disables number/uppercase rules", () => {
    expect(() =>
      assertPasswordStrength("longenoughpassphrase", {
        requireUppercase: false,
        requireNumber: false,
        requireLowercase: true,
      }),
    ).not.toThrow();
  });

  it("enforces a deny-list", () => {
    expect(() =>
      assertPasswordStrength("Password1", { denyList: new Set(["password1"]) }),
    ).toThrow(WeakPasswordError);
  });

  it("reports every failed rule at once", () => {
    try {
      assertPasswordStrength("ab", { requireSymbol: true });
      expect.unreachable();
    } catch (err) {
      const rules = (err as WeakPasswordError).failedRules;
      expect(rules).toContain("minLength:8");
      expect(rules).toContain("requireUppercase");
      expect(rules).toContain("requireNumber");
      expect(rules).toContain("requireSymbol");
    }
  });
});
