import { Hono } from "hono"
import { timing } from "hono/timing"
import { validator } from "hono/validator"

import * as v from "valibot"
import { Resend } from "resend"

import { sha256hex } from "@/lib/crypto"
import { storeToken } from "@/lib/password"
import type { AppEnv } from "@/types"

import { resetPasswordContract } from "./contracts"

export const passwordForgotRoute = new Hono<AppEnv>()

passwordForgotRoute.post(
  "/password/forgot",
  timing({ totalDescription: "password-forgot-request" }),
  validator("json", async (body, c) => {
    const parsed = v.safeParse(resetPasswordContract, body)
    if (parsed.success) return parsed.output

    const logger = c.var.getLogger({ route: "auth.forgot.validator" })
    const issues = v.flatten(parsed.issues).nested

    logger.warn("password:forgot:validation:failed", {
      event: "validation.failed",
      scope: "validator.schema",
      input: parsed.output,
      issues,
    })

    return c.var.responder.error("Invalid input", issues)
  }),
  async (c): Promise<Response> => {
    const { email } = c.req.valid("json")
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
      const { error } = await resend.emails.send({
        from: "me@mail.gambonny.com",
        to: "gambonny@gmaail.com",
        subject: "Your password reset token",
        html: `<p>Your reset token is <strong>${rawToken}</strong>. It expires in 1 hour.</p>`,
      })

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
