import type { MiddlewareHandler } from "hono"
import type { UnknownRecord } from "type-fest"

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
  console.info("thread: ", thread)

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

/**
 * Middleware that injects the `resource_url` into all JSON responses.
 *
 * This acts as a structural postcondition: every response that returns
 * JSON must include a `resource_url`, indicating the backend resource
 * that fulfilled the request.
 *
 * - It enables frontend systems to validate and log which backend route
 *   handled the signal without manually wiring URLs through handlers.
 * - It reinforces structural transparency by ensuring traceable response origins.
 * - It avoids polluting handler logic with metadata concerns, preserving
 *   separation between intent and system instrumentation.
 *
 * This middleware must run *after* the handler logic. It intercepts the
 * response, clones it, and appends the computed `resource_url`.
 *
 * Non-JSON responses are ignored. If the original response is not valid JSON,
 * this middleware will not interfere.
 */
export const withResourceUrl: MiddlewareHandler = async (c, next) => {
  await next()

  const res = c.res
  const contentType = res.headers.get("Content-Type") || ""

  if (!contentType.includes("application/json")) return

  let body: UnknownRecord
  try {
    body = await res.clone().json()
  } catch {
    return
  }

  const resourceUrl = new URL(c.req.url)
  const responseWithUrl = {
    ...body,
    resource_url: resourceUrl.origin + resourceUrl.pathname,
  }

  // Replace response with enriched version
  c.res = new Response(JSON.stringify(responseWithUrl), {
    status: res.status,
    headers: new Headers(res.headers),
  })
}
