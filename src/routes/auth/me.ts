import { Hono } from "hono"
import { timing } from "hono/timing"
import { getCookie } from "hono/cookie"

import type { AppEnv } from "@types"

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
      const user = await c.var.backoff(
        () => c.env.AUTH_SENTINEL.validateToken(token),
        {
          retry: (err, attempt) => {
            const isNetworkError = err instanceof TypeError
            const isServerError = err?.status >= 500

            if (isNetworkError || isServerError) {
              logger.warn("sentinel.validateToken retry", {
                attempt,
                error: err.message,
              })
              return true
            }

            return false
          },
        },
      )

      if (!user) {
        logger.error("invalid:token", { token })
        return http.error("token invalid", {}, 401)
      }

      return http.success("token active", user)
    } catch (err: unknown) {
      logger.error("error:validating:token", { error: (err as Error).message })

      return http.error("an unknown error occurred", {}, 500)
    }
  },
)
