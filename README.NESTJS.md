# NestJS integration example.
An injectable AuthService wrapping the
auth-core instance, plus a guard that maps AuthError -> Nest's
UnauthorizedException/HttpException.

```ts
import {
  CanActivate,
  ExecutionContext,
  HttpException,
  Injectable,
  UnauthorizedException,
} from "@nestjs/common";
import { createAuth, AuthError, type Auth } from "@auth-core/core";
import { createArgon2Driver } from "@auth-core/hashing";
import { MemoryRevocationStore, MemorySessionStore } from "@auth-core/memory";

@Injectable()
export class AuthService {
  readonly auth: Auth = createAuth({
    hashing: { driver: createArgon2Driver() },
    jwt: {
      keys: [{ kid: "k1", algorithm: "HS256", privateKey: process.env.JWT_SECRET! }],
      issuer: "my-app",
      audience: "my-app-clients",
    },
    stores: { revocation: new MemoryRevocationStore(), session: new MemorySessionStore() },
  });
}

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private readonly authService: AuthService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    const header: string | undefined = req.headers.authorization;
    const token = header?.startsWith("Bearer ") ? header.slice(7) : undefined;
    if (!token) throw new UnauthorizedException("missing_token");

    try {
      const payload = await this.authService.auth.verifyAccessToken(token);
      req.userId = payload.sub;
      return true;
    } catch (err) {
      if (err instanceof AuthError) {
        throw new HttpException({ error: err.code, message: err.message }, err.httpStatus);
      }
      throw err;
    }
  }
}

// Usage in a controller:
//
// @Controller("me")
// export class MeController {
//   constructor(private readonly authService: AuthService) {}
//
//   @UseGuards(AuthGuard)
//   @Get()
//   me(@Req() req: any) {
//     return { userId: req.userId };
//   }
// }
```
