import { Hono } from "hono"
import { cors } from "hono/cors"
import { uaBlocker } from "@hono/ua-blocker"
import { aiBots, useAiRobotsTxt } from "@hono/ua-blocker/ai-bots"
import { trimTrailingSlash } from "hono/trailing-slash"
import { contextStorage } from "hono/context-storage"

import { env, WorkflowEntrypoint } from "cloudflare:workers"
import type { WorkflowEvent, WorkflowStep } from "cloudflare:workers"

import { Resend } from "resend"
import { useLogger } from "@gambonny/cflo"

import routes from "@/routes"
import responderMiddleware from "@/middlewares/responder"
import hasherMiddleware from "@/middlewares/hasher"
import { backoffMiddleware } from "@/middlewares/backoff"
import type { AppEnv, SignupWorkflowEnv, SignupWorkflowParams } from "@types"
import traceparent from "./middlewares/traceparent"

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

    // Step 2: Wait for 1 hour
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

app.use(traceparent)
app.use(
  cors({
    origin: env.ALLOWED_ORIGINS.split(","),
    credentials: true,
  }),
)
app.use(contextStorage())
app.use(responderMiddleware)
app.use(trimTrailingSlash())
app.use(uaBlocker({ blocklist: aiBots }))
app.use("/robots.txt", useAiRobotsTxt())

app.use(
  backoffMiddleware({
    numOfAttempts: 5,
    startingDelay: 200, // ms
    maxDelay: 2000, // ms
    jitter: "full",
  }),
)

app.use(async (c, next) => {
  return useLogger({
    level: env.LOG_LEVEL,
    format: env.LOG_FORMAT,
    context: {
      appName: "auth-worker",
      deployId: env.CF_VERSION_METADATA.id,
      traceparent: c.get("traceparent"),
    },
  })(c, next)
})

app.use(hasherMiddleware)
app.route("/", routes)

app.notFound(c => {
  return c.text("Not found", 404)
})

app.onError((_, c) => {
  return c.var.responder.error("Internal error", {}, 500)
})

export default app
