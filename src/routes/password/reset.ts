import { Hono } from "hono"
import { setMetric, timing } from "hono/timing"
import { validator } from "hono/validator"

import * as v from "valibot"

import { hashPassword, sha256hex } from "@/lib/crypto"
import { removeToken, verifyToken } from "@password/service"
import { resetPasswordPayloadSchema } from "@password/schemas"

import type { AppEnv } from "@types"
import type { ResetPasswordPayload } from "@password/schemas"

export const passwordResetRoute = new Hono<AppEnv>()

passwordResetRoute.post(
  "/password/reset",
  timing({ totalDescription: "password-reset-request" }),
  validator("json", async (body, c) => {
    const validation = v.safeParse(resetPasswordPayloadSchema, body)
    if (validation.success) return validation.output

    const logger = c.var.getLogger({ route: "auth.reset.validator" })

    logger.warn("password:reset:validation:failed", {
      event: "validation.failed",
      scope: "validator.schema",
      input: validation.output,
      issues: v.flatten(validation.issues).nested,
    })

    return c.var.responder.error("Invalid input")
  }),
  async (c): Promise<Response> => {
    const { token, password } = c.req.valid("json") as ResetPasswordPayload
    const http = c.var.responder

    // hash the provided token to compare against stored hash
    const hashedToken = await sha256hex(token)
    const email = await verifyToken(c.env, hashedToken)

    const logger = c.var.getLogger({
      route: "auth.reset.handler",
      ...(email ? { hashed_email: c.var.hash(email) } : {}),
    })

    if (!email) {
      logger.warn("reset-token:expired", {
        event: "reset-token.expired",
        scope: "kv.reset-token",
      })

      return http.error("Token has expired, please request a new one", {}, 410)
    }

    // try to find a user with that email
    const user = await c.env.DB.prepare(
      "SELECT id, salt FROM users WHERE email = ?",
    )
      .bind(email)
      .first<{ id: number; salt: string }>()

    if (!user) {
      logger.warn("password:reset:failed:user:notfound", {
        event: "email.notfound",
        scope: "db.users",
      })

      return http.error("User not found", {}, 404) //TODO: return a more generic message
    }

    // hash the new password with existing salt
    const passwordHash = await hashPassword(password, user.salt)

    const result = await c.env.DB.prepare(
      `UPDATE users SET password_hash = ?
       WHERE id = ?`,
    )
      .bind(passwordHash, user.id)
      .run()

    setMetric(c, "db.duration", result.meta.duration)

    logger.info("password:reset:success", {
      event: "password.reset.success",
      scope: "db.users",
    })

    await removeToken(c.env, hashedToken)
    return http.success("Password has been successfully reset")
  },
)
