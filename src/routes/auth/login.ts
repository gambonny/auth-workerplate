import { Hono } from "hono"
import { timing } from "hono/timing"
import { validator } from "hono/validator"
import { setCookie } from "hono/cookie"

import * as v from "valibot"
import { sign as jwtSign } from "@tsndr/cloudflare-worker-jwt"

import { hashPassword } from "@lib/crypto"
import { loginContract } from "@auth/contracts"

import type { AppEnv } from "@types"

export const loginRoute = new Hono<AppEnv>()

loginRoute.post(
  "/login",
  timing({ totalDescription: "login-request" }),
  validator("json", async (body, c) => {
    const validation = v.safeParse(loginContract, body)
    if (validation.success) return validation.output

    const logger = c.var.getLogger({ route: "auth.login.validator" })
    const issues = v.flatten(validation.issues).nested

    logger.warn("login:validation:failed", {
      event: "validation.failed",
      scope: "validator.schema",
      input: validation.output,
      issues,
    })

    return c.var.responder.error("Invalid input", issues, 400)
  }),
  async (c): Promise<Response> => {
    const logger = c.var.getLogger({ route: "auth.login.handler" })
    const { email, password } = c.req.valid("json")
    const http = c.var.responder

    logger.info("login:started", {
      event: "login.attempt",
      scope: "auth.session",
      input: { email },
    })

    // 4) Fetch user by email
    const row = await c.env.DB.prepare(
      `SELECT id, password_hash, salt, active
         FROM users
        WHERE email = ?`,
    )
      .bind(email)
      .first<{
        id: number
        password_hash: string
        salt: string
        active: number
      }>()

    // 5) Check existence & activation
    if (!row || row.active !== 1) {
      logger.warn("login:failed", {
        event: "login.invalid-credentials",
        scope: "auth.session",
        input: { email },
      })

      return http.error("Invalid email or password", {}, 401)
    }

    // 6) Verify password
    const computed = await hashPassword(password, row.salt)
    if (computed !== row.password_hash) {
      logger.warn("login:failed", {
        event: "login.invalid-credentials",
        scope: "auth.session",
        input: { email },
      })

      return http.error("Invalid email or password", {}, 401)
    }

    // 7) Issue tokens
    const now = Math.floor(Date.now() / 1000)
    const accessPayload = { id: row.id, email, exp: now + 60 * 60 }
    const refreshPayload = { id: row.id, email, exp: now + 60 * 60 * 24 * 14 }

    const accessToken = await jwtSign(accessPayload, "secretito")
    const refreshToken = await jwtSign(refreshPayload, "secretito")

    // 8) Set cookies
    setCookie(c, "token", accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: "None",
      maxAge: 60 * 60,
      path: "/",
    })
    setCookie(c, "refresh_token", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "None",
      maxAge: 60 * 60 * 24 * 14,
      path: "/",
    })

    logger.info("login:success", {
      event: "login.success",
      scope: "auth.session",
      input: { userId: row.id },
    })

    return http.success("Logged in successfully")
  },
)
