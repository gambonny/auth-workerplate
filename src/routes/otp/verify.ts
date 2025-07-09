import { Hono } from "hono"
import { setCookie } from "hono/cookie"
import { timing, setMetric } from "hono/timing"
import { validator } from "hono/validator"

import * as v from "valibot"
import { sign as jwtSign } from "@tsndr/cloudflare-worker-jwt"

import { verifyOtp } from "@/lib/otp"
import type { AppEnv } from "@/types"

import { otpContract } from "./contracts"

export const otpRoute = new Hono<AppEnv>()

otpRoute.post(
  "/otp/verify",
  timing({ totalDescription: "otp-verify-request" }),
  validator("json", async (body, c) => {
    const validation = v.safeParse(otpContract, body)
    if (validation.success) return validation.output

    const logger = c.var.getLogger({ route: "otp.verify.validator" })
    const issues = v.flatten(validation.issues).nested

    logger.warn("otp:validation:failed", {
      event: "validation.failed",
      scope: "validator.schema",
      input: validation.output,
      issues,
    })

    return c.var.responder.error("Input invalid", issues, 400)
  }),
  async (c): Promise<Response> => {
    const { email, otp } = c.req.valid("json")
    const logger = c.var.getLogger({ route: "otp.verify.handler" })

    logger.info("otp:started", {
      event: "handler.started",
      scope: "handler.init",
      input: { email },
    })

    const { ok, reason } = await verifyOtp(c.env, email, otp)

    if (!ok) {
      switch (reason) {
        case "expired":
          logger.warn("otp:expired", {
            event: "otp.expired",
            scope: "kv.otp",
            input: { email, otp }, //TODO: opaque these values
          })

          return c.var.responder.error(
            "OTP has expired, please request a new one",
            {},
            410,
          )
        case "too_many":
          logger.warn("otp:too many attempts", {
            event: "otp.blocked",
            scope: "kv.otp",
            input: { email, otp }, //TODO: opaque these values
          })

          return c.var.responder.error("Too many attempts", {}, 429)
        default:
          return c.var.responder.error("OTP is invalid", {}, 400)
      }
    }

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
          input: { email, otp }, //TODO: opaque these values
        })
        return c.var.responder.error("an error occurred", {}, 400)
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
        }

        const refreshPayload = {
          id: user.id,
          email,
          exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 14,
        }

        const accessToken = await jwtSign(accessPayload, "secretito") //TODO:
        const refreshToken = await jwtSign(refreshPayload, "secretito")

        setCookie(c, "token", accessToken, {
          httpOnly: true,
          secure: true,
          sameSite: "None",
          maxAge: 3600,
          path: "/",
        })

        setCookie(c, "refresh_token", refreshToken, {
          httpOnly: true,
          secure: true,
          sameSite: "None",
          maxAge: 60 * 60 * 24 * 14,
          path: "/",
        })

        return c.var.responder.success("user activated", 200)
      }

      logger.warn("user:activated:failed", {
        event: "user.activation.failed",
        scope: "db.users",
        input: { otp },
      })

      return c.var.responder.error("activation failed", {}, 400)
    } catch (err) {
      logger.error("db:error", {
        event: "db.error",
        scope: "db.users",
        error: err instanceof Error ? err.message : String(err),
      })

      return c.var.responder.error("Unkown error", {}, 500)
    }
  },
)
