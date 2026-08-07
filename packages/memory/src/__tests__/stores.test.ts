import { describe, expect, it } from "vitest";
import { MemoryRevocationStore } from "../revocation-store.js";
import { MemorySessionStore } from "../session-store.js";

function future(seconds: number): number {
  return Math.floor(Date.now() / 1000) + seconds;
}

describe("MemoryRevocationStore", () => {
  it("reports unrevoked jtis as not revoked", async () => {
    const store = new MemoryRevocationStore({ sweepIntervalMs: 0 });
    expect(await store.isRevoked("unknown")).toBe(false);
  });

  it("revokes and reports a jti", async () => {
    const store = new MemoryRevocationStore({ sweepIntervalMs: 0 });
    await store.revoke({ jti: "abc", expiresAt: future(60), reason: "logout" });
    expect(await store.isRevoked("abc")).toBe(true);
  });

  it("treats expired revocation entries as not-revoked and sweeps them", async () => {
    const store = new MemoryRevocationStore({ sweepIntervalMs: 0 });
    await store.revoke({ jti: "abc", expiresAt: Math.floor(Date.now() / 1000) - 1 });
    expect(await store.isRevoked("abc")).toBe(false);
    expect(store.size).toBe(0);
  });

  it("revokeMany revokes a batch", async () => {
    const store = new MemoryRevocationStore({ sweepIntervalMs: 0 });
    await store.revokeMany([
      { jti: "a", expiresAt: future(60) },
      { jti: "b", expiresAt: future(60) },
    ]);
    expect(await store.isRevoked("a")).toBe(true);
    expect(await store.isRevoked("b")).toBe(true);
  });
});

describe("MemorySessionStore", () => {
  it("creates and finds a session", async () => {
    const store = new MemorySessionStore();
    const created = await store.create({ jti: "j1", userId: "u1", expiresAt: future(60) });
    expect(created.jti).toBe("j1");
    const found = await store.find("j1");
    expect(found?.userId).toBe("u1");
  });

  it("returns null for an expired session and evicts it", async () => {
    const store = new MemorySessionStore();
    await store.create({ jti: "j1", userId: "u1", expiresAt: Math.floor(Date.now() / 1000) - 1 });
    expect(await store.find("j1")).toBeNull();
    expect(store.size).toBe(0);
  });

  it("rotate() marks the old session consumed and creates a successor", async () => {
    const store = new MemorySessionStore();
    await store.create({ jti: "j1", userId: "u1", expiresAt: future(60) });
    const next = await store.rotate("j1", { jti: "j2", userId: "u1", expiresAt: future(60) });
    expect(next.rotatedFrom).toBe("j1");

    const old = await store.find("j1");
    expect(old?.consumedAt).toBeTypeOf("number");
  });

  it("deleteByUser removes every session for that user", async () => {
    const store = new MemorySessionStore();
    await store.create({ jti: "j1", userId: "u1", expiresAt: future(60) });
    await store.create({ jti: "j2", userId: "u1", expiresAt: future(60) });
    await store.create({ jti: "j3", userId: "u2", expiresAt: future(60) });

    await store.deleteByUser("u1");

    expect(await store.find("j1")).toBeNull();
    expect(await store.find("j2")).toBeNull();
    expect(await store.find("j3")).not.toBeNull();
  });
});
