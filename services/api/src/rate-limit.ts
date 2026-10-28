/**
 * Durable Object rate limiter: one instance per limit key (sharded via idFromName(key)).
 * POST { limit, windowMs } -> { limited: boolean, count }
 * State resets when the window expires. Counters are metadata only (no user data).
 */
export class RateLimiter {
  private state: DurableObjectState;
  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    const { limit, windowMs } = (await request.json()) as { limit: number; windowMs: number };
    const now = Date.now();
    const stored = await this.state.storage.get<{ count: number; resetAt: number }>("counter");
    if (!stored || now > stored.resetAt) {
      await this.state.storage.put("counter", { count: 1, resetAt: now + windowMs });
      return Response.json({ limited: false, count: 1 });
    }
    stored.count += 1;
    await this.state.storage.put("counter", stored);
    return Response.json({ limited: stored.count > limit, count: stored.count });
  }
}

interface DurableObjectNamespaceLike {
  idFromName(name: string): unknown;
  get(id: unknown): { fetch(input: string, init?: RequestInit): Promise<Response> };
}

/** Build an app-level limiter backed by a Durable Object namespace. */
export function durableObjectLimiter(ns: DurableObjectNamespaceLike) {
  return async (key: string, limit: number, windowMs: number): Promise<boolean> => {
    try {
      const stub = ns.get(ns.idFromName(key));
      const res = await stub.fetch("https://rate-limit/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ limit, windowMs }),
      });
      const data = (await res.json()) as { limited: boolean };
      return data.limited;
    } catch {
      return false; // fail open: a limiter outage must not lock every user out
    }
  };
}
