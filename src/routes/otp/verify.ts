import { Hono } from "hono"
import { timing, setMetric } from "hono/timing"
import { validator } from "hono/validator"

import * as v from "valibot"
import { sign as jwtSign } from "@tsndr/cloudflare-worker-jwt"

import { verifyOtp } from "@otp/service"
import { otpPayloadSchema } from "@otp/schemas"

import type { AppEnv } from "@types"
import type { UserPayload } from "@auth/schemas"
import type { OtpPayload } from "@otp/schemas"
import { issueAuthCookies } from "@/lib/cookies"

export const verifyOtpRoute = new Hono<AppEnv>()

verifyOtpRoute.post(
  "/otp/verify",
  timing({ totalDescription: "otp-verify-request" }),
  validator("json", async (body, c) => {
    const validation = v.safeParse(otpPayloadSchema, body)

    if (validation.success) return validation.output

    const logger = c.var.getLogger({ route: "otp.verify.validator" })

    logger.warn("otp:validation:failed", {
      event: "validation.failed",
      scope: "validator.schema",
      input: validation.output,
      issues: v.flatten(validation.issues).nested,
    })

    return c.var.responder.error("Input invalid")
  }),
  async (c): Promise<Response> => {
    const { email, otp } = c.req.valid("json") as OtpPayload
    const http = c.var.responder
    const logger = c.var.getLogger({
      route: "otp.verify.handler",
      hashed_email: c.var.hash(email),
    })

    logger.debug("otp:started", {
      event: "handler.started",
      scope: "handler.init",
    })

    const verified = await verifyOtp(c.env, email, otp, issues => {
      logger.warn("otp:verification:failed", {
        event: "otp.verification.failed",
        scope: "kv.otp",
        input: { otp },
        issues,
      })
    })

    if (!verified) return http.error("activation failed")

    try {
      const user = await c.env.DB.prepare(
        "SELECT id FROM users WHERE email = ?  AND active = false",
      )
        .bind(email)
        .first<{ id: string }>()

      if (!user) {
        logger.warn("user:get:failed", {
          event: "user.not.found",
          scope: "db.users",
        })

        return http.error("activation failed")
      }

      const result = await c.env.DB.prepare(
        "UPDATE users SET active = true WHERE email = ?",
      )
        .bind(email)
        .run()

      if (result.meta.changes === 1) {
        logger.info("user:activated", {
          event: "user.validated",
          scope: "db.users",
          input: { db: { duration: result.meta.duration } },
        })

        setMetric(c, "db.duration", result.meta.duration)

        const accessPayload = {
          id: user.id,
          email,
          exp: Math.floor(Date.now() / 1000) + 60 * 60,
        } satisfies UserPayload

        const refreshPayload = {
          id: user.id,
          email,
          exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 14,
        } satisfies UserPayload

        const accessToken = await jwtSign(accessPayload, c.env.JWT_TOKEN)
        const refreshToken = await jwtSign(refreshPayload, c.env.JWT_TOKEN)
        issueAuthCookies(c, accessToken, refreshToken)

        return http.success("user activated")
      }

      logger.warn("user:activated:failed", {
        event: "user.activation.failed",
        scope: "db.users",
        input: { otp },
      })

      return http.error("activation failed")
    } catch (err) {
      logger.error("db:error", {
        event: "db.error",
        scope: "db.users",
        error: err instanceof Error ? err.message : String(err),
      })

      return http.error("Unknown error", {}, 500)
    }
  },
)
