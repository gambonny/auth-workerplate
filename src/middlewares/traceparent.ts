import { createMiddleware } from "hono/factory"

/**
 * Middleware that enforces presence of the `traceparent` header.
 *
 * This acts as a structural contract: every incoming request must be
 * traceable to a client-triggered interaction. By requiring a traceparent ID:
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
const traceparent = createMiddleware(async (c, next) => {
  c.env.ALLOWED_ORIGINS.split(",").map((origin: string) => {
    c.header("Timing-Allow-Origin", origin)
  })

  const traceparent = c.req.header("traceparent")

  if (!traceparent) {
    console.warn("request.rejected", {
      reason: "missing_traceparent",
      path: c.req.path,
      traceparent,
    })

    return c.text("Bad request", 400)
  }

  c.set("traceparent", traceparent)

  await next()
})

export default traceparent
