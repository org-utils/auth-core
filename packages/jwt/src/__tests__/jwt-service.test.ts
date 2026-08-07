import { describe, expect, it } from "vitest";
import {
  ClaimValidationError,
  ExpiredTokenError,
  InvalidAlgorithmError,
} from "@auth-core/shared";
import { JwtService } from "../jwt-service.js";

function makeService(overrides: Partial<ConstructorParameters<typeof JwtService>[0]> = {}) {
  return new JwtService({
    keys: [{ kid: "k1", algorithm: "HS256", privateKey: "test-secret-key-0123456789" }],
    issuer: "acme",
    audience: "acme-app",
    accessTokenTtlSeconds: 900,
    refreshTokenTtlSeconds: 2_592_000,
    ...overrides,
  });
}

describe("JwtService", () => {
  it("signs and verifies an access token", async () => {
    const jwt = makeService();
    const token = await jwt.signAccessToken({ sub: "user-1" });
    const payload = await jwt.verifyAccessToken(token);
    expect(payload.sub).toBe("user-1");
    expect(payload.type).toBe("access");
    expect(payload.iss).toBe("acme");
    expect(payload.aud).toBe("acme-app");
    expect(typeof payload.jti).toBe("string");
  });

  it("rejects an access token verified as a refresh token", async () => {
    const jwt = makeService();
    const token = await jwt.signAccessToken({ sub: "user-1" });
    await expect(jwt.verifyRefreshToken(token)).rejects.toBeInstanceOf(ClaimValidationError);
  });

  it("supports arbitrary custom token types via the generic API", async () => {
    const jwt = makeService();
    const token = await jwt.signToken(
      { sub: "user-1", type: "password-reset", purpose: "forgot-password" },
      600,
    );
    const payload = await jwt.verifyToken(token, {
      expectedClaims: { type: "password-reset", purpose: "forgot-password" },
    });
    expect(payload.sub).toBe("user-1");
  });

  it("rejects when expectedClaims don't match", async () => {
    const jwt = makeService();
    const token = await jwt.signToken({ sub: "user-1", type: "magic-link" }, 600);
    await expect(
      jwt.verifyToken(token, { expectedClaims: { type: "invitation" } }),
    ).rejects.toBeInstanceOf(ClaimValidationError);
  });

  it("expires tokens after their TTL", async () => {
    const jwt = makeService({ clockToleranceSeconds: 0 });
    const token = await jwt.signToken({ sub: "user-1", type: "api-key" }, 1);
    await new Promise((r) => setTimeout(r, 1300));
    await expect(jwt.verifyToken(token)).rejects.toBeInstanceOf(ExpiredTokenError);
  });

  it("rejects tokens using an algorithm outside the allow-list", async () => {
    const signer = new JwtService({
      keys: [{ kid: "k1", algorithm: "HS256", privateKey: "secret-a-0123456789" }],
    });
    const verifier = new JwtService({
      keys: [{ kid: "k1", algorithm: "HS384", privateKey: "secret-a-0123456789" }],
      allowedAlgorithms: ["HS384"],
    });
    const token = await signer.signToken({ sub: "x", type: "access" }, 60);
    await expect(verifier.verifyToken(token)).rejects.toThrow();
  });

  it("supports multiple keys and rotation via kid", async () => {
    const jwt = new JwtService({
      keys: [
        { kid: "old", algorithm: "HS256", privateKey: "old-secret-0123456789" },
        { kid: "new", algorithm: "HS256", privateKey: "new-secret-0123456789" },
      ],
      currentKid: "new",
    });
    const tokenFromOldKey = await jwt.signToken({ sub: "u1", type: "access" }, 60, { kid: "old" });
    const payload = await jwt.verifyToken(tokenFromOldKey);
    expect(payload.sub).toBe("u1");
    expect(jwt.keyIds).toEqual(["old", "new"]);
  });

  it("decodeToken reads claims without verifying the signature", async () => {
    const jwt = makeService();
    const token = await jwt.signAccessToken({ sub: "user-1" });
    const { payload, header } = jwt.decodeToken(token);
    expect(payload.sub).toBe("user-1");
    expect(header.alg).toBe("HS256");
  });
});
