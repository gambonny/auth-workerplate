import { Hono } from "hono"
import { timing } from "hono/timing"
import { setCookie } from "hono/cookie"

import authMiddleware from "@/middlewares/auth"
import type { AppEnv } from "@/types"

export const logoutRoute = new Hono<AppEnv>()
logoutRoute.use(timing({ totalDescription: "logout-request" }))
logoutRoute.use(authMiddleware)

logoutRoute.post("/logout", async c => {
  const logger = c.var.getLogger({ route: "auth.logout.handler" })

  logger.log("user:logout", {
    event: "logout.started",
    scope: "auth.session",
  })

  // Expire the tokens by setting maxAge=0
  setCookie(c, "token", "", {
    httpOnly: true,
    secure: true,
    sameSite: "None",
    path: "/",
    maxAge: 0,
  })

  setCookie(c, "refresh_token", "", {
    httpOnly: true,
    secure: true,
    sameSite: "None",
    path: "/",
    maxAge: 0,
  })

  logger.log("user:logout:success", {
    event: "logout.success",
    scope: "auth.session",
  })

  return c.var.responder.success("Logged out")
})
