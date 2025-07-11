import { Hono } from "hono"
import { timing } from "hono/timing"
import { validator } from "hono/validator"

import * as v from "valibot"
import { backOff } from "exponential-backoff"
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
    const logger = c.var.getLogger({ route: "auth.forgot.handler" })
    const http = c.var.responder

    logger.info("password:forgot:started", {
      event: "handler.started",
      scope: "auth.password",
      input: { email },
    })

    // generate token + hash
    const rawToken = crypto.randomUUID()
    const tokenHash = await sha256hex(rawToken)

    // store in KV, log on failure
    const stored = await storeToken(c.env, email, tokenHash, issues => {
      logger.error("password:forgot:token-store-failed", {
        event: "kv.password.storing.failed",
        scope: "kv.password",
        input: { email },
        issues,
      })
    })

    if (!stored) {
      return http.error(
        "Failed to generate reset token, please try again later",
        {},
        500,
      )
    }

    logger.info("password:forgot:token-generated", {
      event: "token.generated",
      scope: "kv.password",
      input: { email },
    })

    // send email
    try {
      const resend = new Resend(c.env.RESEND)
      const { error } = await backOff(
        () =>
          resend.emails.send({
            from: "me@mail.gambonny.com",
            to: "gambonny@gmail.com",
            subject: "Your password reset token",
            html: `<p>Your reset token is <strong>${rawToken}</strong>. It expires in 1 hour.</p>`,
          }),
        {
          jitter: "full",
          startingDelay: 100,
          timeMultiple: 2,
          maxDelay: 1000,
          numOfAttempts: 4,
          retry: e => {
            // retry only on transient network or 5xx errors
            if (e instanceof Error && e.message.includes("429")) return true
            if (e instanceof Error && e.message.includes("timeout")) return true
            if (e instanceof Error && e.message.match(/^5\d\d/)) return true
            return false
          },
        },
      )

      if (error) throw new Error(error.message)

      return http.created(
        "If that email is registered, you’ll receive reset instructions shortly",
      )
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      logger.error("password:forgot:email-send-failed", {
        event: "email.send.failed",
        scope: "auth.password",
        input: { email },
        error: msg,
      })
      return http.error(
        "Failed to send reset email, please try again later",
        {},
        500,
      )
    }
  },
)
