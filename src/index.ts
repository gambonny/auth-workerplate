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
import {
  forgotPasswordContract,
  loginContract,
  otpContract,
  resetPasswordContract,
  signupContract,
} from "./contracts"
import {
  generateOtp,
  hashPassword,
  salt,
  sha256hex,
  makeResponder,
} from "./generators"
// import { requireThread } from "./middlewares"

import {
  WorkflowEntrypoint,
  type WorkflowEvent,
  type WorkflowStep,
} from "cloudflare:workers"
import type { SignupWorkflowEnv, SignupWorkflowParams } from "./types"
import type { TimingVariables } from "hono/timing"
import type { UnknownRecord } from "type-fest"
import { Resend } from "resend"
import { contextStorage } from "hono/context-storage"
import { responderMiddleware } from "./middlewares"

type TokenSentinelService = {
  validateToken: (token: string) => Promise<false | UnknownRecord>
}

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

const app = new Hono<{
  Bindings: CloudflareBindings
  Variables: {
    thread: string
    getLogger: GetLoggerFn
    responder: ReturnType<typeof makeResponder>
  } & TimingVariables
}>()

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
  //todo: max 3 tries
  "/otp/verify",
  timing({ totalDescription: "otp-verify" }),
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

    return c.var.responder("Input invalid", issues, 400)
  }),
  async (c): Promise<Response> => {
    const { email, otp } = c.req.valid("json")
    const logger = c.var.getLogger({ route: "auth.otp.handler" })

    logger.info("otp:started", {
      event: "handler.started",
      scope: "handler.init",
      input: { email },
    })

    try {
      const user = await c.env.DB.prepare(
        "SELECT id FROM users WHERE email = ? AND otp = ? AND active = false",
      )
        .bind(email, otp)
        .first()

      if (!user) {
        logger.warn("user:activated:failed", {
          event: "otp.invalid",
          scope: "db.users",
          input: { email, otp }, //TODO: opaque these values
        })
        return c.var.responder.error(
          "Invalid OTP or already activated",
          {},
          400,
        )
      }

      const result = await c.env.DB.prepare(
        "UPDATE users SET active = true WHERE email = ? and otp = ?",
      )
        .bind(email, otp)
        .run()

      if (result.meta.changes === 1) {
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
        event: "otp.invalid",
        scope: "db.users",
        input: { otp },
      })

      return c.var.responder.error("otp invalid", {}, 400)
    } catch (err) {
      logger.error("otp:error", {
        event: "db.error",
        scope: "db.users",
        error: err instanceof Error ? err.message : String(err),
      })

      return c.var.responder.error("Unkown error", {}, 500)
    }
  },
)

app.post(
  "/signup",
  timing({ totalDescription: "signup-request" }),
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

    const r = makeResponder()
    return c.json(r.error("Input invalid", issues), 400)
  }),
  async (c): Promise<Response> => {
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

      return c.var.responder.created(
        "User registered, email with otp has been sent",
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

          return c.var.responder.error(
            "Invalid input",
            { email: ["User already exists"] },
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

      return c.var.responder.error(errorMessage, {}, 500)
    }
  },
)

app.post(
  "/refresh",
  timing({ totalDescription: "refresh-request" }),
  async c => {
    const refreshToken = getCookie(c, "refresh_token")
    if (!refreshToken)
      return c.var.responder.error("Missing refresh token", {}, 401)

    const isValid = await jwtVerify(refreshToken, "secretito")
    if (!isValid) return c.var.responder.error("Invalid refresh token", {}, 401)

    const decoded = jwtDecode(refreshToken).payload as {
      id?: string
      email?: string
    }

    if (!decoded?.email)
      return c.var.responder.error("Malformed token", {}, 400)

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

    return c.var.responder.success("Access token refreshed")
  },
)

//todo: cache response
app.get(
  "/me",
  timing({ totalDescription: "me-request" }),
  async (c): Promise<Response> => {
    const logger = c.var.getLogger({ route: "auth.me.handler" })
    const token = getCookie(c, "token")

    if (!token) {
      logger.error("Invalid token")
      return c.var.responder.success("token invalid", 401)
    }

    const sentinel = c.env.AUTH_SENTINEL as unknown as TokenSentinelService
    const user = await sentinel.validateToken(token)

    if (user) {
      return c.var.responder.success("token active", user)
    }

    return c.var.responder.error("token invalid", {}, 401)
  },
)

app.post("/logout", timing({ totalDescription: "logout-request" }), async c => {
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

  return c.var.responder.success("Logged out", 200)
})

app.post(
  "/password/forgot",
  timing({ totalDescription: "password-forgot-request" }),
  validator("json", async (body, c) => {
    const validation = v.safeParse(forgotPasswordContract, body)
    if (validation.success) return validation.output

    const logger = c.var.getLogger({ route: "auth.forgot.validator" })
    const issues = v.flatten(validation.issues).nested

    logger.warn("password:forgot:validation:failed", {
      event: "validation.failed",
      scope: "validator.schema",
      input: validation.output,
      issues,
    })

    return c.var.responder.error("Invalid input", issues, 400)
  }),
  async (c): Promise<Response> => {
    const { email } = c.req.valid("json")
    const logger = c.var.getLogger({ route: "auth.forgot.handler" })

    // generate token + hash + expiry
    const rawToken = crypto.randomUUID()
    const tokenHash = await sha256hex(rawToken)
    const expires = Math.floor(Date.now() / 1000) + 60 * 60 // 1h

    // store only the hash + expiry
    await c.env.DB.prepare(
      `UPDATE users
         SET reset_token_hash = ?, reset_expires = ?
       WHERE email = ?`,
    )
      .bind(tokenHash, expires, email)
      .run()

    logger.info("password:forgot:token-generated", {
      event: "token.generated",
      scope: "db.users",
      input: { email },
    })

    const resend = new Resend(env.RESEND)
    const { error } = await resend.emails.send({
      from: "me@mail.gambonny.com",
      to: "gambonny@gmail.com",
      subject: "Your token",
      html: `<p>Your token is <strong>${rawToken}</strong> you have 60 minutes</p>`,
    })

    if (error) throw new Error(error.message)

    return c.var.responder.created(
      "If that email is registered, you’ll receive reset instructions shortly",
      200,
    )
  },
)

app.post(
  "/password/reset",
  timing({ totalDescription: "password-reset-request" }),
  validator("json", async (body, c) => {
    const validation = v.safeParse(resetPasswordContract, body)
    if (validation.success) return validation.output

    const logger = c.var.getLogger({ route: "auth.reset.validator" })
    const issues = v.flatten(validation.issues).nested

    logger.warn("password:reset:validation:failed", {
      event: "validation.failed",
      scope: "validator.schema",
      input: validation.output,
      issues,
    })

    return c.var.responder.error("Invalid input", issues, 400)
  }),
  async (c): Promise<Response> => {
    const logger = c.var.getLogger({ route: "auth.reset.handler" })
    const { token, password } = c.req.valid("json")

    // hash the provided token to compare against stored hash
    const hashedToken = await sha256hex(token)

    // try to find a user with that reset_token_hash
    const user = await c.env.DB.prepare(
      "SELECT id, email, salt, reset_expires FROM users WHERE reset_token_hash = ?",
    )
      .bind(hashedToken)
      .first<{
        id: number
        email: string
        salt: string
        reset_expires: number
      }>()

    if (!user) {
      logger.warn("password:reset:failed:notfound", {
        event: "reset.token.notfound",
        scope: "db.users",
      })

      return c.var.responder.error("Reset token is invalid", {}, 400)
    }

    if (user.reset_expires < Math.floor(Date.now() / 1000)) {
      logger.warn("password:reset:failed:expired", {
        event: "reset.token.expired",
        scope: "db.users",
        input: { email: user.email },
      })
      return c.var.responder.error("Reset token has expired", {}, 400)
    }

    // hash the new password with existing salt (or generate new salt if you want)
    const passwordHash = await hashPassword(password, user.salt)

    const result = await c.env.DB.prepare(
      `UPDATE users
         SET password_hash = ?, reset_token_hash = NULL, reset_expires = NULL
       WHERE id = ?`,
    )
      .bind(passwordHash, user.id)
      .run()

    setMetric(c, "db.duration", result.meta.duration)

    logger.info("password:reset:success", {
      event: "password.reset.success",
      scope: "db.users",
      input: { email: user.email },
    })

    return c.var.responder.success("Password has been successfully reset", 200)
  },
)

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
    const computed = await hashPassword(password, row.salt)
    if (computed !== row.password_hash) {
      logger.warn("login:failed", {
        event: "login.invalid-credentials",
        scope: "auth.session",
        input: { email },
      })

      return c.var.responder.success("Invalid email or password", 401)
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

export default app
