import { createApp } from "./app";
import { D1Store } from "./store/d1";

export interface Env {
  DB: D1Database;
  ATTACHMENTS?: R2Bucket;
  ALLOW_REGISTRATION?: string;
  TURNSTILE_SECRET?: string;
}

export default {
  fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const app = createApp(new D1Store(env.DB as never), {
      allowRegistration: env.ALLOW_REGISTRATION !== "false",
    });
    return app.fetch(request, env, ctx);
  },
};
