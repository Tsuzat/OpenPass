import { createApp } from "./app";
import { D1Store } from "./store/d1";
import { R2BlobStore } from "./store/blobs";
import { durableObjectLimiter } from "./rate-limit";

export { RateLimiter } from "./rate-limit";

export interface Env {
  DB: D1Database;
  ATTACHMENTS?: R2Bucket;
  RATE_LIMITER?: DurableObjectNamespace;
  ALLOW_REGISTRATION?: string;
  TURNSTILE_SECRET?: string;
}

export default {
  fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const app = createApp(new D1Store(env.DB as never), {
      allowRegistration: env.ALLOW_REGISTRATION !== "false",
      blobs: env.ATTACHMENTS ? new R2BlobStore(env.ATTACHMENTS as never) : undefined,
      rateLimiter: env.RATE_LIMITER ? durableObjectLimiter(env.RATE_LIMITER as never) : undefined,
    });
    return app.fetch(request, env, ctx);
  },
};
