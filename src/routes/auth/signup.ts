import { Hono } from "hono"
import { timing, setMetric } from "hono/timing"
import { validator } from "hono/validator"

import * as v from "valibot"

import { hashPassword, salt } from "@lib/crypto"
import { generateOtp, storeOtp } from "@otp/service"
import { signupPayloadContract } from "@auth/contracts"

import type { AppEnv } from "@types"
import type { SignupPayload } from "@auth/contracts"

export const signupRoute = new Hono<AppEnv>()

signupRoute.post(
  "/signup",
  timing({ totalDescription: "signup-request" }),
  validator("json", async (body, c) => {
    const validation = v.safeParse(signupPayloadContract, body)
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
    const logger = c.var.getLogger({ route: "auth.signup.handler" })
    const http = c.var.responder

    logger.debug("signup:started", {
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
        "INSERT INTO users (email, password_hash, salt) VALUES (?, ?, ?)",
      )
        .bind(email, passwordHash, generatedSalt)
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

      const otpStored = await storeOtp(c.env, email, otp, issues => {
        logger.error("otp:store:failed", {
          event: "kv.otp.storing.failed",
          scope: "vk.otp",
          input: { email },
          issues,
        })
      })

      if (otpStored) {
        const workflow = await c.env.SIGNUP_WFW.create({
          params: { email, otp },
        })

        logger.info("workflow:created", {
          event: "workflow.created",
          scope: "workflow.signup",
          workflow: workflow.id,
        })

        return http.created("User registered, email with otp has been sent")
      }

      return http.error("User registerd but email with otp couldn't be sent")
    } catch (err) {
      if (err instanceof Error) {
        if (err.message.includes("UNIQUE constraint failed")) {
          logger.warn("user:registration:failed:email:taken", {
            event: "db.insert.conflict",
            scope: "db.users",
            reason: "email taken",
            input: { email },
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
