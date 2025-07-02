import { uaBlocker } from "@hono/ua-blocker"
import { aiBots, useAiRobotsTxt } from "@hono/ua-blocker/ai-bots"
import { env } from "cloudflare:workers"
import { cors } from "hono/cors"
import { timing, setMetric } from "hono/timing"
import { Hono } from "hono"
import { secureHeaders } from "hono/secure-headers"
import { trimTrailingSlash } from "hono/trailing-slash"
import { validator } from "hono/validator"
import * as v from "valibot"

import {
  sign as jwtSign,
  decode as jwtDecode,
  verify as jwtVerify,
} from "@tsndr/cloudflare-worker-jwt"

import { getCookie, setCookie } from "hono/cookie"
import { type GetLoggerFn, useLogger } from "@gambonny/cflo"
import { otpContract, signupContract } from "./contracts"
import {
  generateOtp,
  hashPassword,
  withError,
  withSuccess,
  salt,
} from "./generators"
import { requireThread, withResourceUrl } from "./middlewares"

import {
  WorkflowEntrypoint,
  type WorkflowEvent,
  type WorkflowStep,
} from "cloudflare:workers"
import type { SignupWorkflowEnv, SignupWorkflowParams } from "./types"
import type { TimingVariables } from "hono/timing"
import type { UnknownRecord } from "type-fest"

type TokenSentinelService = {
  validateToken: (token: string) => Promise<false | UnknownRecord>
}

export class SignupWorkflow extends WorkflowEntrypoint<
  SignupWorkflowEnv,
  SignupWorkflowParams
> {
  async run(event: WorkflowEvent<SignupWorkflowParams>, step: WorkflowStep) {
    const { email } = event.payload

    // Step 1: Send OTP email
    // await step.do(
    //   "send-otp-email",
    //   { retries: { limit: 1, delay: 0 } },
    //   async () => {
    //     const resend = new Resend(this.env.RESEND)
    //     const { error, data } = await resend.emails.send({
    //       from: "send@gambonny.com",
    //       to: email,
    //       subject: "Your one-time password",
    //       html: `<p>Your OTP is <strong>${otp}</strong></p>`,
    //     })
    //
    //     if (error) throw new Error(error.message)
    //     console.log("data: ", data)
    //   },
    // )

    // Step 2: Wait for 1 minute
    await step.sleep("wait-for-activation", "5 minutes")

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

const app = new Hono<{
  Bindings: CloudflareBindings
  Variables: { thread: string; getLogger: GetLoggerFn } & TimingVariables
}>()

app.use(cors({ origin: "http://localhost:5173", credentials: true }))
app.use(secureHeaders())
app.use(trimTrailingSlash())
app.use(requireThread)
// Block all AI bots
app.use(
  "*",
  uaBlocker({
    blocklist: aiBots,
  }),
)

// Serve robots.txt to discourage AI bots
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
  //todo: max 3 tries
  "/otp/verify",
  validator("json", async (body, c) => {
    const validation = v.safeParse(otpContract, body)
    if (validation.success) return validation.output

    const logger = c.var.getLogger({ route: "auth.otp.validator" })
    const issues = v.flatten(validation.issues).nested

    logger.warn("otp:validation:failed", {
      event: "validation.failed",
      scope: "validator.schema",
      input: validation.output,
      issues,
    })

    return c.json(withError("Input invalid", issues), 400)
  }),
  timing({ totalDescription: "full-request" }),
  withResourceUrl,
  async (c): Promise<Response> => {
    c.header("Timing-Allow-Origin", "http://localhost:5173")
    const { email, otp } = c.req.valid("json")
    const logger = c.var.getLogger({ route: "auth.otp.handler" })

    logger.info("otp:started", {
      event: "handler.started",
      scope: "handler.init",
      input: { email },
    })

    try {
      const user = await c.env.DB.prepare(
        // "SELECT id FROM users WHERE email = ? AND otp = ? AND activated = false",
        "SELECT id FROM users WHERE email = ? AND activated = false",
      )
        // .bind(email, otp)
        .bind(email)
        .first()

      if (!user) {
        logger.warn("user:activated:failed", {
          event: "otp.invalid",
          scope: "db.users",
          input: { email, otp }, // opaque these values
        })
        return c.json(withError("Invalid OTP or already activated"), 400)
      }

      const result = await c.env.DB.prepare(
        "UPDATE users SET activated = true WHERE email = ? and otp = ?",
      )
        .bind(email, otp)
        .run()

      // if (result.meta.changes === 1) {
      logger.info("user:activated", {
        event: "otp.validated",
        scope: "db.users",
        input: { db: { duration: result.meta.duration } },
      })

      setMetric(c, "db.duration", result.meta.duration)

      const accessPayload = {
        id: user.id,
        email,
        exp: Math.floor(Date.now() / 1000) + 60 * 60,
      }

      logger.warn("user", { user })

      const refreshPayload = {
        id: user.id,
        email,
        exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 14,
      }

      const accessToken = await jwtSign(accessPayload, "secretito")
      const refreshToken = await jwtSign(refreshPayload, "secretito")

      logger.warn("access token", { accessPayload })
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

      return c.json(withSuccess("user activated"), 200)
      // }

      // logger.warn("user:activated:failed", {
      //   event: "otp.invalid",
      //   scope: "db.users",
      //   input: { otp },
      // })
      //
      // return c.json(withError("otp invalid"), 400)
    } catch (err) {
      logger.error("otp:error", {
        event: "db.error",
        scope: "db.users",
        error: err instanceof Error ? err.message : String(err),
      })

      return c.json(withError("Unkown error"), 500)
    }
  },
)

app.post(
  "/signup",
  validator("json", async (body, c) => {
    const validation = v.safeParse(signupContract, body)
    if (validation.success) return validation.output

    const logger = c.var.getLogger({ route: "auth.signup.validator" })
    const issues = v.flatten(validation.issues).nested

    logger.warn("signup:validation:failed", {
      event: "validation.failed",
      scope: "validator.schema",
      input: validation.output,
      issues,
    })

    return c.json(withError("Input invalid", issues), 400)
  }),
  timing({ totalDescription: "full-request" }),
  withResourceUrl,
  async (c): Promise<Response> => {
    c.header("Timing-Allow-Origin", "http://localhost:5173")
    const { email, password } = c.req.valid("json")
    const logger = c.var.getLogger({ route: "auth.signup.handler" })

    logger.info("signup:started", {
      event: "handler.started",
      scope: "handler.init",
      input: { email },
    })

    try {
      logger.debug("generating:credentials", {
        event: "crypto.init",
        scope: "crypto.password",
      })

      const generatedSalt = salt()
      const passwordHash = await hashPassword(password, generatedSalt)
      const otp = generateOtp()

      logger.debug("preparing:user:registration", {
        event: "db.insert.started",
        scope: "db.users",
        input: { email },
      })

      const result = await c.env.DB.prepare(
        "INSERT INTO users (email, password_hash, salt, otp) VALUES (?, ?, ?, ?)",
      )
        .bind(email, passwordHash, generatedSalt, otp)
        .run()

      setMetric(c, "db.duration", result.meta.duration)
      logger.info("user:registered", {
        event: "db.insert.success",
        scope: "db.users",
        input: {
          email,
          db: {
            duration: result.meta.duration,
          },
        },
      })

      const workflow = await c.env.SIGNUP_WFW.create({ params: { email, otp } })

      logger.debug("workflow:created", {
        event: "workflow.created",
        scope: "db.users",
        workflow,
      })

      return c.json(
        withSuccess("User registered, email with otp has been sent"),
        201,
      )
    } catch (err) {
      if (err instanceof Error) {
        if (err.message.includes("UNIQUE constraint failed")) {
          logger.warn("user:registration:failed:email:taken", {
            event: "db.insert.conflict",
            scope: "db.users",
            reason: "email taken",
            input: { email },
          })

          return c.json(
            withError("Invalid input", { email: ["User already exists"] }),
            409,
          )
        }
      }

      const errorMessage = err instanceof Error ? err.message : String(err)

      logger.error("user:registration:error", {
        event: "signup.error",
        scope: "db.users",
        error: errorMessage,
      })

      return c.json(withError(errorMessage), 500)
    }
  },
)

app.post("/refresh", async c => {
  const refreshToken = getCookie(c, "refresh_token")
  if (!refreshToken) return c.json(withError("Missing refresh token"), 401)

  const isValid = await jwtVerify(refreshToken, "secretito")
  if (!isValid) return c.json(withError("Invalid refresh token"), 401)

  const decoded = jwtDecode(refreshToken).payload as {
    id?: string
    email?: string
  }

  if (!decoded?.email) return c.json(withError("Malformed token"), 400)

  const newAccessToken = await jwtSign(
    {
      id: decoded.id,
      email: decoded.email,
      exp: Math.floor(Date.now() / 1000) + 60 * 60,
    },
    "secretito",
  )

  setCookie(c, "token", newAccessToken, {
    httpOnly: true,
    secure: true,
    sameSite: "None",
    maxAge: 3600,
    path: "/",
  })

  return c.json(withSuccess("Access token refreshed"))
})

//todo: cache response
app.get(
  "/me",
  timing({ totalDescription: "full-request" }),
  withResourceUrl,
  async (c): Promise<Response> => {
    const logger = c.var.getLogger({ route: "auth.me.handler" })
    const token = getCookie(c, "token")

    if (!token) {
      logger.error("Invalid token")
      return c.json(withError("token invalid"), 401)
    }

    const sentinel = c.env.AUTH_SENTINEL as unknown as TokenSentinelService
    const user = await sentinel.validateToken(token)

    if (user) {
      return c.json(withSuccess("token active", user))
    }

    return c.json(withError("token invalid"), 401)
  },
)

app.post("/logout", async c => {
  const logger = c.var.getLogger({ route: "auth.logout.handler" })

  logger.info("user:logout", {
    event: "logout.started",
    scope: "auth.session",
  })

  // Expire the tokens by setting maxAge=0
  setCookie(c, "token", "", {
    httpOnly: true,
    secure: true,
    sameSite: "None",
    path: "/",
    maxAge: 0,
  })

  setCookie(c, "refresh_token", "", {
    httpOnly: true,
    secure: true,
    sameSite: "None",
    path: "/",
    maxAge: 0,
  })

  logger.info("user:logout:success", {
    event: "logout.success",
    scope: "auth.session",
  })

  return c.json(withSuccess("Logged out"), 200)
})

app.notFound(c => {
  return c.text("Not found", 404)
})

export default app
