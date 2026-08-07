# Next.js (App Router) integration example.

lib/auth.ts — shared Auth instance


```ts
import { createAuth } from "@auth-core/core";
import { createArgon2Driver } from "@auth-core/hashing";
import { MemoryRevocationStore, MemorySessionStore } from "@auth-core/memory";

export const auth = createAuth({
  hashing: { driver: createArgon2Driver() },
  jwt: {
    keys: [{ kid: "k1", algorithm: "HS256", privateKey: process.env.JWT_SECRET! }],
    issuer: "my-app",
    audience: "my-app-clients",
  },
  stores: { revocation: new MemoryRevocationStore(), session: new MemorySessionStore() },
});

/**
 * app/api/login/route.ts
 */
// import { NextRequest, NextResponse } from "next/server";
// import { auth } from "@/lib/auth";
//
// export async function POST(req: NextRequest) {
//   const { userId } = await req.json();
//   const { accessToken, refreshToken } = await auth.login({ userId });
//
//   const res = NextResponse.json({ accessToken });
//   res.cookies.set("refresh_token", refreshToken, {
//     httpOnly: true,
//     secure: true,
//     sameSite: "strict",
//   });
//   return res;
// }

/**
 * app/api/refresh/route.ts
 */
// import { NextRequest, NextResponse } from "next/server";
// import { auth, AuthError } from "@auth-core/core"; // re-exported errors
//
// export async function POST(req: NextRequest) {
//   const refreshToken = req.cookies.get("refresh_token")?.value;
//   if (!refreshToken) return NextResponse.json({ error: "missing_token" }, { status: 401 });
//
//   try {
//     const rotated = await auth.rotateRefreshToken(refreshToken);
//     const res = NextResponse.json({ accessToken: rotated.accessToken });
//     res.cookies.set("refresh_token", rotated.refreshToken, {
//       httpOnly: true,
//       secure: true,
//       sameSite: "strict",
//     });
//     return res;
//   } catch (err) {
//     if (err instanceof AuthError) {
//       return NextResponse.json({ error: err.code }, { status: err.httpStatus });
//     }
//     throw err;
//   }
// }

/**
 * middleware.ts — gate protected routes at the edge
 */
// import { NextRequest, NextResponse } from "next/server";
// import { auth } from "@/lib/auth";
//
// export async function middleware(req: NextRequest) {
//   const token = req.headers.get("authorization")?.replace("Bearer ", "");
//   if (!token) return NextResponse.redirect(new URL("/login", req.url));
//
//   try {
//     await auth.verifyAccessToken(token);
//     return NextResponse.next();
//   } catch {
//     return NextResponse.redirect(new URL("/login", req.url));
//   }
// }
//
// export const config = { matcher: ["/dashboard/:path*"] };

```
