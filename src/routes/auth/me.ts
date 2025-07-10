import { Hono } from "hono"
import { timing } from "hono/timing"
import { getCookie } from "hono/cookie"

import type { AppEnv, TokenSentinelService } from "@/types"

export const meRoute = new Hono<AppEnv>()
meRoute.use(timing({ totalDescription: "me-request" }))

meRoute.get("/me", async (c): Promise<Response> => {
  const logger = c.var.getLogger({ route: "auth.me.handler" })
  const token = getCookie(c, "token")

  if (!token) {
    logger.log("token:not:present")
    return c.var.responder.error("issues with token", {}, 401)
  }

  try {
    const sentinel = c.env.AUTH_SENTINEL as unknown as TokenSentinelService
    const user = await sentinel.validateToken(token)

    if (!user) {
      logger.error("invalid:token", { token })
      return c.var.responder.error("token invalid", {}, 401)
    }

    return c.var.responder.success("token active", user)
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e)
    logger.error("error:validating:token", { error: msg })
    return c.var.responder.error("an unknown error occurred", {}, 500)
  }
})
