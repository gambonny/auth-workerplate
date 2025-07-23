import { getCookie } from "hono/cookie"
import { createMiddleware } from "hono/factory"

import type { AppEnv } from "@types"

const authMiddleware = createMiddleware<AppEnv>(async (c, next) => {
  if (!c.var.getLogger || !c.var.responder) {
    throw new Error("authMiddleware mis‑ordered: logger/responder missing")
  }

  const logger = c.var.getLogger({ route: "auth.middleware" })
  const http = c.var.responder

  const token = getCookie(c, "token")
  if (!token) {
    logger.warn("auth:missing-token", {
      event: "auth.missing_token",
      scope: "pre.sentinel.validation",
      path: c.req.path,
    })

    return http.error("Unauthorized", {}, 401)
  }

  const isValid = await c.env.AUTH_SENTINEL.validateToken(token)

  if (!isValid) {
    logger.warn("auth:invalid-token", {
      event: "auth.invalid_token",
      scope: "post.sentinel.validation",
      path: c.req.path,
    })

    return http.error("Unauthorized", {}, 401)
  }

  await next()
})

export default authMiddleware
