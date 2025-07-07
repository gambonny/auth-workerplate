import type { MiddlewareHandler } from "hono"
import type { UnknownRecord } from "type-fest"
import { makeResponder } from "./generators"
import { createMiddleware } from "hono/factory"

/**
 * Middleware that enforces presence of the `x-thread-id` header.
 *
 * This acts as a structural contract: every incoming request must be
 * traceable to a client-triggered interaction. By requiring a thread ID:
 *
 * - We guarantee that no request enters the system without an identifiable origin.
 * - We enable end-to-end correlation between consumers actions and backend logs.
 * - We reduce attack surface by rejecting unstructured or synthetic traffic.
 *
 * Requests missing this header are rejected with a vague 400 response,
 * preserving system intent without revealing internal requirements.
 *
 * This middleware should run first, before logger setup or route handling.
 */
export const requireThread: MiddlewareHandler = async (c, next) => {
  const thread = c.req.header("x-thread-id")

  if (!thread) {
    console.warn("request.rejected", {
      reason: "missing_thread_id",
      path: c.req.path,
      thread,
    })

    return c.text("Bad request", 400)
  }

  c.set("thread", thread)

  await next()
}

export const responderMiddleware = createMiddleware(async (c, next) => {
  c.set("responder", makeResponder())
  await next()
})
