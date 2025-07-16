import { Hono } from "hono"
import { setMetric, timing } from "hono/timing"
import { validator } from "hono/validator"

import * as v from "valibot"

import { hashPassword, sha256hex } from "@/lib/crypto"
import { resetTokenKey, verifyToken } from "@password/service"
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
    const logger = c.var.getLogger({ route: "auth.reset.handler" })

    const hashedToken = await sha256hex(token)

    let email: string | false
    try {
      email = await c.var.backoff(
        () =>
          verifyToken(c.env, hashedToken, issues => {
            logger.warn("password:reset:token:malformed", {
              event: "reset-token.malformed",
              scope: "kv.reset-token.schema",
              issues,
            })
          }),
        {
          retry: (err, attempt) => {
            logger.debug("password:reset:token-verify-retry", {
              attempt,
              error: err instanceof Error ? err.message : String(err),
            })

            return true
          },
        },
      )

      if (!email) {
        return http.error(
          "Token has expired, please request a new one",
          {},
          410,
        )
      }
    } catch (err: unknown) {
      logger.error("password:reset:token-verify-failed", {
        event: "kv.password.verify.failed",
        scope: "kv.password",
        error: err instanceof Error ? err.message : String(err),
      })

      return http.error("Token verification failed, please try again", {}, 500)
    }

    const user = await c.env.DB.prepare(
      "SELECT id, salt FROM users WHERE email = ?",
    )
      .bind(email)
      .first<{ id: number; salt: string }>()

    if (!user) {
      logger.warn("password:reset:user-notfound", {
        event: "email.notfound",
        scope: "db.users",
      })

      return http.error("User not found", {}, 404)
    }

    const passwordHash = await hashPassword(password, user.salt)
    const result = await c.env.DB.prepare(
      "UPDATE users SET password_hash = ? WHERE id = ?",
    )
      .bind(passwordHash, user.id)
      .run()

    setMetric(c, "db.duration", result.meta.duration)
    logger.info("password:reset:success", {
      event: "password.reset.success",
      scope: "db.users",
    })

    try {
      await c.env.OTP_STORE.delete(resetTokenKey(token))
    } catch {}

    return http.success("Password has been successfully reset")
  },
)
