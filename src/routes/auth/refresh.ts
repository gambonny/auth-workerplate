import { Hono } from "hono"
import { timing } from "hono/timing"
import { getCookie, setCookie } from "hono/cookie"

import {
  sign as jwtSign,
  decode as jwtDecode,
  verify as jwtVerify,
} from "@tsndr/cloudflare-worker-jwt"
import * as v from "valibot"

import type { AppEnv } from "@/types"
import { userPayloadContract, type UserPayload } from "./contracts"

export const refreshRoute = new Hono<AppEnv>()
refreshRoute.use(timing({ totalDescription: "refresh-request" }))

refreshRoute.post("refresh", async c => {
  const refreshToken = getCookie(c, "refresh_token")
  if (!refreshToken) {
    return c.var.responder.error("Missing refresh token", {}, 401)
  }

  const verified = await jwtVerify(refreshToken, "secretito")
  if (!verified) {
    return c.var.responder.error("Invalid refresh token", {}, 401)
  }

  const { success, output: userPayload } = v.safeParse(
    userPayloadContract,
    jwtDecode(refreshToken).payload,
  )

  if (!success) {
    return c.var.responder.error("Malformed token")
  }

  const newAccessToken = await jwtSign(
    {
      ...userPayload,
      exp: Math.floor(Date.now() / 1000) + 60 * 60,
    } satisfies UserPayload,
    "secretito",
  )

  setCookie(c, "token", newAccessToken, {
    httpOnly: true,
    secure: true,
    sameSite: "None",
    maxAge: 3600,
    path: "/",
  })

  return c.var.responder.success("Access token refreshed")
})
