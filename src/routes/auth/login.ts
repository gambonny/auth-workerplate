import { Hono } from "hono"
import { timing } from "hono/timing"
import { validator } from "hono/validator"

import * as v from "valibot"
import { sign as jwtSign } from "@tsndr/cloudflare-worker-jwt"

import { hashPassword } from "@lib/crypto"
import { loginPayloadSchema } from "@auth/schemas"

import type { AppEnv } from "@types"
import type { LoginPayload } from "@auth/schemas"
import { issueAuthCookies } from "@/lib/cookies"

export const loginRoute = new Hono<AppEnv>()

loginRoute.post(
  "/login",
  timing({ totalDescription: "login-request" }),
  validator("json", async (body, c) => {
    const validation = v.safeParse(loginPayloadSchema, body)
    if (validation.success) return validation.output

    c.var
      .getLogger({ route: "auth.login.validator" })
      .warn("login:validation:failed", {
        event: "validation.failed",
        scope: "validator.schema",
        input: validation.output,
        issues: v.flatten(validation.issues).nested,
      })

    return c.var.responder.error("Invalid input")
  }),
  async (c): Promise<Response> => {
    const { email, password } = c.req.valid("json") as LoginPayload
    const http = c.var.responder
    const logger = c.var.getLogger({
      route: "auth.login.handler",
      hashed_email: c.var.hash(email),
    })

    logger.debug("login:started", {
      event: "login.attempt",
      scope: "auth.session",
    })

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

    if (!row || row.active !== 1) {
      logger.warn("email:not:found", {
        event: "email.not.found",
        scope: "db.users",
        reason: "user doesn't exist in the database",
      })

      return http.error("Invalid email or password", {}, 401)
    }

    const computed = await hashPassword(password, row.salt)
    if (computed !== row.password_hash) {
      logger.warn("login:failed", {
        event: "login.invalid-credentials",
        scope: "auth.session",
      })

      return http.error("Invalid email or password", {}, 401)
    }

    const now = Math.floor(Date.now() / 1000)
    const accessPayload = { id: row.id, email, exp: now + 60 * 60 }
    const refreshPayload = { id: row.id, email, exp: now + 60 * 60 * 24 * 14 }

    try {
      const accessToken = await jwtSign(accessPayload, c.env.JWT_TOKEN)
      const refreshToken = await jwtSign(refreshPayload, c.env.JWT_TOKEN)
      issueAuthCookies(c, accessToken, refreshToken)

      logger.info("login:success", {
        event: "login.success",
        scope: "auth.session",
        input: { userId: row.id },
      })

      return http.success("Logged in successfully")
    } catch (e: unknown) {
      return http.error(String(e))
    }
  },
)
