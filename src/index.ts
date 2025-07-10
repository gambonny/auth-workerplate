import { uaBlocker } from "@hono/ua-blocker"
import { aiBots, useAiRobotsTxt } from "@hono/ua-blocker/ai-bots"
import { env } from "cloudflare:workers"
import { cors } from "hono/cors"
import { timing } from "hono/timing"
import { Hono } from "hono"
import { secureHeaders } from "hono/secure-headers"
import { trimTrailingSlash } from "hono/trailing-slash"
import { validator } from "hono/validator"
import * as v from "valibot"

import { sign as jwtSign } from "@tsndr/cloudflare-worker-jwt"

import { setCookie } from "hono/cookie"
import { useLogger } from "@gambonny/cflo"
import { loginContract } from "./contracts"
import * as generator from "./generators"
// import { requireThread } from "./middlewares"

import {
  WorkflowEntrypoint,
  type WorkflowEvent,
  type WorkflowStep,
} from "cloudflare:workers"
import type { AppEnv, SignupWorkflowEnv, SignupWorkflowParams } from "./types"
import { Resend } from "resend"
import { contextStorage } from "hono/context-storage"
import { responderMiddleware } from "./middlewares"
/// ---
import routes from "./routes"

export class SignupWorkflow extends WorkflowEntrypoint<
  SignupWorkflowEnv,
  SignupWorkflowParams
> {
  async run(event: WorkflowEvent<SignupWorkflowParams>, step: WorkflowStep) {
    const { email, otp } = event.payload

    // Step 1: Send OTP email
    await step.do(
      "send-otp-email",
      { retries: { limit: 1, delay: 0 } },
      async () => {
        const resend = new Resend(this.env.RESEND)
        const { error } = await resend.emails.send({
          from: "me@mail.gambonny.com",
          to: "gambonny@gmail.com",
          subject: "Your one-time password",
          html: `<p>Your OTP is <strong>${otp}</strong></p>`,
        })

        if (error) throw new Error(error.message)
      },
    )

    // Step 2: Wait for 1 minute
    await step.sleep("wait-for-activation", "60 minutes")

    // Step 3: Check if user is activated
    const isUserActive = await step.do("check-activation", async () => {
      const result = await this.env.DB.prepare(
        "SELECT activated from users WHERE email = ?",
      )
        .bind(email)
        .first<{ activated: number }>()

      return result?.activated ?? 0
    })

    if (!isUserActive) {
      // Step 4: Delete unactivated user
      await step.do("delete-user", async () => {
        await this.env.DB.prepare("DELETE from users WHERE email = ?")
          .bind(email)
          .run()
      })
    }
  }
}

const app = new Hono<AppEnv>()

app.use(
  cors({
    origin: ["http://localhost:4173", "http://localhost:5173"],
    credentials: true,
  }),
)
app.use(secureHeaders())
app.use(trimTrailingSlash())
app.use(contextStorage())
app.use(responderMiddleware)
// app.use(requireThread)
app.use("*", uaBlocker({ blocklist: aiBots }))
app.use("/robots.txt", useAiRobotsTxt())

app.use(async (c, next) => {
  return useLogger({
    level: env.LOG_LEVEL,
    format: env.LOG_FORMAT,
    context: {
      appName: "auth-worker",
      deployId: env.CF_VERSION_METADATA.id,
      thread: c.get("thread"),
    },
  })(c, next)
})

app.post(
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

      return c.var.responder.error("Invalid email or password", {}, 401)
    }

    // 6) Verify password
    const computed = await generator.hashPassword(password, row.salt)
    if (computed !== row.password_hash) {
      logger.warn("login:failed", {
        event: "login.invalid-credentials",
        scope: "auth.session",
        input: { email },
      })

      return c.var.responder.error("Invalid email or password", {}, 401)
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

    return c.var.responder.success("Logged in successfully", 200)
  },
)

app.notFound(c => {
  return c.text("Not found", 404)
})

app.route("/", routes)

export default app
