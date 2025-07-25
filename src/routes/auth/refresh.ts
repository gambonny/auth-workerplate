import { Hono } from "hono"
import { timing } from "hono/timing"
import { getCookie } from "hono/cookie"

import {
  sign as jwtSign,
  decode as jwtDecode,
  verify as jwtVerify,
} from "@tsndr/cloudflare-worker-jwt"
import * as v from "valibot"

import type { AppEnv } from "@types"
import { userPayloadSchema, type UserPayload } from "@auth/schemas"
import { setSecureCookie } from "@/lib/cookies"

export const refreshRoute = new Hono<AppEnv>()

refreshRoute.post(
  "refresh",
  timing({ totalDescription: "refresh-request" }),
  async c => {
    const http = c.var.responder
    const refreshToken = getCookie(c, "refresh_token")
    if (!refreshToken) {
      return http.error("Missing refresh token", {}, 401)
    }

    const verified = await jwtVerify(refreshToken, c.env.JWT_TOKEN)
    if (!verified) {
      return http.error("Invalid refresh token", {}, 401)
    }

    const { success, output: userPayload } = v.safeParse(
      userPayloadSchema,
      jwtDecode(refreshToken).payload,
    )

    if (!success) {
      return http.error("Malformed token")
    }

    const newAccessToken = await jwtSign(
      {
        ...userPayload,
        exp: Math.floor(Date.now() / 1000) + 60 * 60,
      } satisfies UserPayload,
      c.env.JWT_TOKEN,
    )

    setSecureCookie(c, "token", newAccessToken, 60 * 60)

    return http.success("Access token refreshed")
  },
)
