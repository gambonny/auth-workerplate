import { Hono } from "hono"
import { timing, setMetric } from "hono/timing"
import { validator } from "hono/validator"

import * as v from "valibot"

import { hashPassword, salt } from "@lib/crypto"
import { generateOtp, storeOtp } from "@otp/service"
import { signupPayloadSchema } from "@auth/schemas"

import type { AppEnv } from "@types"
import type { SignupPayload } from "@auth/schemas"

export const signupRoute = new Hono<AppEnv>()

signupRoute.post(
  "/signup",
  timing({ totalDescription: "signup-request" }),
  validator("json", async (body, c) => {
    const validation = v.safeParse(signupPayloadSchema, body)
    if (validation.success) return validation.output

    const logger = c.var.getLogger({ route: "auth.signup.validator" })

    logger.warn("signup:validation:failed", {
      event: "validation.failed",
      scope: "validator.schema",
      input: validation.output,
      issues: v.flatten(validation.issues).nested,
    })

    return c.var.responder.error("Input invalid")
  }),
  async (c): Promise<Response> => {
    const { email, password } = c.req.valid("json") as SignupPayload
    const http = c.var.responder
    const logger = c.var.getLogger({
      route: "auth.signup.handler",
      hashed_email: c.var.hash(email),
    })

    logger.debug("signup:started", {
      event: "handler.started",
      scope: "handler.init",
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
      })

      const result = await c.env.DB.prepare(
        "INSERT INTO users (email, password_hash, salt) VALUES (?, ?, ?)",
      )
        .bind(email, passwordHash, generatedSalt)
        .run()

      setMetric(c, "db.duration", result.meta.duration)
      logger.info("user:registered", {
        event: "db.insert.success",
        scope: "db.users",
        input: { db: { duration: result.meta.duration } },
      })

      try {
        const stored = await c.var.backoff(
          () =>
            storeOtp(c.env, email, otp, issues => {
              logger.error("otp:schema:invalid", {
                event: "otp.schema.failed",
                scope: "otp.schema",
                issues,
              })
            }),
          {
            retry: (e, attempt) => {
              logger.debug("otp:store:attempt", {
                input: otp,
                attempt,
                event: "otp.store.attempt",
                scope: "kv.otp.backoff.retry",
                error: e instanceof Error ? e.message : String(e),
              })

              return true
            },
          },
        )

        if (!stored) return http.error("error during otp creation")
      } catch (e: unknown) {
        logger.error("otp:storage:failed", {
          event: "otp.store.failed",
          scope: "kv.otp",
          input: { otp },
          error: e instanceof Error ? e.message : String(e),
        })

        return http.error("unknown error", {}, 500)
      }

      const workflow = await c.env.SIGNUP_WFW.create({
        params: { email, otp },
      })

      logger.info("workflow:created", {
        event: "workflow.created",
        scope: "workflow.signup",
        workflow: workflow.id,
      })

      return http.created("User registered, email with otp has been sent")
    } catch (err) {
      if (err instanceof Error) {
        if (err.message.includes("UNIQUE constraint failed")) {
          logger.warn("user:registration:failed:email:taken", {
            event: "db.insert.conflict",
            scope: "db.users",
            reason: "email taken",
          })

          return http.error(
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

      return http.error(errorMessage, {}, 500)
    }
  },
)
