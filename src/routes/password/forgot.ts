import { Hono } from "hono"
import { timing } from "hono/timing"
import { validator } from "hono/validator"

import * as v from "valibot"
import { Resend } from "resend"

import { sha256hex } from "@lib/crypto"
import { storeToken } from "@password/service"
import { forgotPasswordPayloadSchema } from "@password/schemas"

import type { AppEnv } from "@types"
import type { ForgotPasswordPayload } from "@password/schemas"

export const passwordForgotRoute = new Hono<AppEnv>()

passwordForgotRoute.post(
  "/password/forgot",
  timing({ totalDescription: "password-forgot-request" }),
  validator("json", async (body, c) => {
    const parsed = v.safeParse(forgotPasswordPayloadSchema, body)
    if (parsed.success) return parsed.output

    const logger = c.var.getLogger({ route: "auth.forgot.validator" })

    logger.warn("password:forgot:validation:failed", {
      event: "validation.failed",
      scope: "validator.schema",
      input: parsed.output,
      issues: v.flatten(parsed.issues).nested,
    })

    return c.var.responder.error("Invalid input")
  }),
  async (c): Promise<Response> => {
    const { email } = c.req.valid("json") as ForgotPasswordPayload
    const http = c.var.responder
    const logger = c.var.getLogger({
      route: "auth.forgot.handler",
      hashed_email: c.var.hash(email),
    })

    logger.info("password:forgot:started", {
      event: "handler.started",
      scope: "auth.password",
    })

    const rawToken = crypto.randomUUID()
    const tokenHash = await sha256hex(rawToken)

    try {
      const stored = await c.var.backoff(
        () =>
          storeToken(c.env, email, tokenHash, issues => {
            logger.error("password:forgot:token-store-schema-failed", {
              event: "kv.password.schema.failed",
              scope: "kv.password",
              issues,
            })
          }),
        {
          retry: (err, attempt) => {
            logger.debug("password:forgot:token-store-retry", {
              attempt,
              error: err instanceof Error ? err.message : String(err),
            })
            return true
          },
        },
      )

      if (!stored) {
        return http.error(
          "Failed to generate reset token, please try again later",
          {},
          500,
        )
      }
    } catch (e: unknown) {
      logger.error("password:forgot:token-store-failed", {
        event: "kv.password.store.failed",
        scope: "kv.password",
        error: e instanceof Error ? e.message : String(e),
      })
      return http.error(
        "Failed to generate reset token, please try again later",
        {},
        500,
      )
    }

    logger.info("password:forgot:token-generated", {
      event: "token.generated",
      scope: "kv.password",
    })

    try {
      const resend = new Resend(c.env.RESEND)
      const { error } = await c.var.backoff(
        () =>
          resend.emails.send({
            from: "me@mail.gambonny.com",
            to: "gambonny@gmail.com",
            subject: "Your password reset token",
            html: `<p>Your reset token is <strong>${rawToken}</strong>. It expires in 1 hour.</p>`,
          }),
        {
          retry: (err, attempt) => {
            const msg = err instanceof Error ? err.message : String(err)
            const isTransient =
              msg.includes("429") ||
              msg.includes("timeout") ||
              /^5\d\d/.test(msg)

            if (isTransient) {
              logger.debug("password:forgot:email-retry", {
                attempt,
                error: msg,
              })
            }

            return isTransient
          },
        },
      )

      if (error) throw new Error(error.message)

      return http.created(
        "If that email is registered, you’ll receive reset instructions shortly",
      )
    } catch (err: unknown) {
      logger.error("password:forgot:email-send-failed", {
        event: "email.send.failed",
        scope: "auth.password",
        error: err instanceof Error ? err.message : String(err),
      })

      return http.error(
        "Failed to send reset email, please try again later",
        {},
        500,
      )
    }
  },
)
