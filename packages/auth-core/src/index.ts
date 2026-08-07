export { createAuth, Auth } from "./create-auth.js";
export type { LoginSessionInput, LoginResult } from "./create-auth.js";
export { resolveAuthConfig } from "./config.js";
export type { AuthConfig, ResolvedAuthConfig } from "./config.js";
export { rotateRefreshToken } from "./refresh-rotation.js";
export type { RotateResult } from "./refresh-rotation.js";

// Re-export shared types/errors so consumers only need one import for the common case.
export * from "@auth-core/shared";
