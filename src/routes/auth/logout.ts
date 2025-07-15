import { Hono } from "hono"
import { timing } from "hono/timing"

import authMiddleware from "@/middlewares/auth"
import type { AppEnv } from "@types"
import { clearAuthCookies } from "@/lib/cookies"

export const logoutRoute = new Hono<AppEnv>()

logoutRoute.post(
  "/logout",
  timing({ totalDescription: "logout-request" }),
  authMiddleware,
  async c => {
    const logger = c.var.getLogger({ route: "auth.logout.handler" })

    logger.debug("user:logout", {
      event: "logout.started",
      scope: "auth.session",
    })

    clearAuthCookies(c)

    logger.log("user:logout:success", {
      event: "logout.success",
      scope: "auth.session",
    })

    return c.var.responder.success("Logged out")
  },
)
