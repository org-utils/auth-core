import { describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import { createAuth } from "../create-auth.js";
import { createArgon2Driver } from "@auth-core/hashing";
import { MemoryRevocationStore, MemorySessionStore } from "@auth-core/memory";
import { RefreshReuseDetectedError, RevokedTokenError, WeakPasswordError } from "@auth-core/shared";

function makeAuth() {
  return createAuth({
    hashing: { driver: createArgon2Driver() },
    jwt: {
      keys: [{ kid: "k1", algorithm: "HS256", privateKey: "integration-test-secret-0123456789" }],
      issuer: "auth-core-tests",
      audience: "test-suite",
    },
    tokens: { access: { ttlSeconds: 900 }, refresh: { ttlSeconds: 2_592_000 } },
    stores: { revocation: new MemoryRevocationStore({ sweepIntervalMs: 0 }), session: new MemorySessionStore() },
  });
}

describe("createAuth()", () => {
  it("hashes and verifies passwords, enforcing the strength policy", async () => {
    const auth = makeAuth();
    await expect(auth.hashPassword("weak")).rejects.toBeInstanceOf(WeakPasswordError);
    const hash = await auth.hashPassword("StrongPass1");
    expect(await auth.verifyPassword("StrongPass1", hash)).toBe(true);
    expect(await auth.verifyPassword("wrong", hash)).toBe(false);
  });

  it("login() issues a working access/refresh pair backed by a session", async () => {
    const auth = makeAuth();
    const userId = randomUUID();
    const { accessToken, refreshToken } = await auth.login({ userId, deviceId: "device-a" });
    const access = await auth.verifyAccessToken(accessToken);
    const refresh = await auth.verifyRefreshToken(refreshToken);
    expect(access.sub).toBe(userId);
    expect(refresh.sub).toBe(userId);
  });

  it("rotateRefreshToken() issues a fresh pair and invalidates the old refresh token", async () => {
    const auth = makeAuth();
    const userId = randomUUID();
    const { refreshToken } = await auth.login({ userId });

    const rotated = await auth.rotateRefreshToken(refreshToken);
    expect(rotated.refreshToken).not.toBe(refreshToken);

    // the new access token is immediately usable
    const payload = await auth.verifyAccessToken(rotated.accessToken);
    expect(payload.sub).toBe(userId);
  });

  it("detects refresh token reuse and revokes the whole session family", async () => {
    const auth = makeAuth();
    const userId = randomUUID();
    const { refreshToken } = await auth.login({ userId });

    const rotated = await auth.rotateRefreshToken(refreshToken);

    // Replaying the already-consumed token must fail hard.
    await expect(auth.rotateRefreshToken(refreshToken)).rejects.toBeInstanceOf(RefreshReuseDetectedError);

    // The legitimately-rotated successor is also dead now (mass revocation on reuse).
    await expect(auth.rotateRefreshToken(rotated.refreshToken)).rejects.toThrow();
  });

  it("revokeToken() immediately invalidates a specific token by jti", async () => {
    const auth = makeAuth();
    const userId = randomUUID();
    const { accessToken } = await auth.login({ userId });
    const payload = await auth.verifyAccessToken(accessToken);

    await auth.revokeToken(payload.jti!, payload.exp!);

    await expect(auth.verifyAccessToken(accessToken)).rejects.toBeInstanceOf(RevokedTokenError);
  });

  it("logoutAll() ends every session for a user", async () => {
    const auth = makeAuth();
    const userId = randomUUID();
    const first = await auth.login({ userId, deviceId: "phone" });
    const second = await auth.login({ userId, deviceId: "laptop" });

    await auth.logoutAll(userId);

    await expect(auth.rotateRefreshToken(first.refreshToken)).rejects.toThrow();
    await expect(auth.rotateRefreshToken(second.refreshToken)).rejects.toThrow();
  });

  it("logout() ends only the targeted session", async () => {
    const auth = makeAuth();
    const userId = randomUUID();
    const phone = await auth.login({ userId, deviceId: "phone" });
    const laptop = await auth.login({ userId, deviceId: "laptop" });

    const phoneRefreshPayload = await auth.verifyRefreshToken(phone.refreshToken);
    await auth.logout(phoneRefreshPayload.jti!);

    await expect(auth.rotateRefreshToken(phone.refreshToken)).rejects.toThrow();
    // laptop session is untouched
    const rotated = await auth.rotateRefreshToken(laptop.refreshToken);
    expect(rotated.accessToken).toBeTypeOf("string");
  });
});
