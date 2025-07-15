import { Hono } from "hono"
import { timing } from "hono/timing"
import { getCookie } from "hono/cookie"

import type { AppEnv, TokenSentinelService } from "@types"

export const meRoute = new Hono<AppEnv>()

meRoute.get(
  "/me",
  timing({ totalDescription: "me-request" }),
  async (c): Promise<Response> => {
    const logger = c.var.getLogger({ route: "auth.me.handler" })
    const token = getCookie(c, "token")
    const http = c.var.responder

    if (!token) {
      logger.log("token:not:present")
      return http.error("issues with token", {}, 401)
    }

    try {
      logger.log("token:sentinel:started")
      const sentinel = c.env.AUTH_SENTINEL as unknown as TokenSentinelService
      const user = await sentinel.validateToken(token)

      if (!user) {
        logger.error("invalid:token", { token })
        return http.error("token invalid", {}, 401)
      }

      return http.success("token active", user)
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e)
      logger.error("error:validating:token", { error: msg })
      return http.error("an unknown error occurred", {}, 500)
    }
  },
)
