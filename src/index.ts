import { Hono } from "hono"
import { cors } from "hono/cors"
import { uaBlocker } from "@hono/ua-blocker"
import { aiBots, useAiRobotsTxt } from "@hono/ua-blocker/ai-bots"
import { secureHeaders } from "hono/secure-headers"
import { trimTrailingSlash } from "hono/trailing-slash"
import { contextStorage } from "hono/context-storage"

import { env, WorkflowEntrypoint } from "cloudflare:workers"
import type { WorkflowEvent, WorkflowStep } from "cloudflare:workers"

import { Resend } from "resend"
import { useLogger } from "@gambonny/cflo"

import routes from "@/routes"
import responderMiddleware from "@/middlewares/responder"
import hasherMiddleware from "@/middlewares/hasher"
// import traceparent from "@/middlewares/traceparent"
import type { AppEnv, SignupWorkflowEnv, SignupWorkflowParams } from "@types"

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

app.use(
  cors({
    origin: ["http://localhost:4173", "http://localhost:5173"], // TODO: from config file
    credentials: true,
  }),
)
// app.use(traceparent)
app.use(contextStorage())
app.use(responderMiddleware)
app.use(secureHeaders())
app.use(trimTrailingSlash())
app.use(uaBlocker({ blocklist: aiBots }))
app.use("/robots.txt", useAiRobotsTxt())

app.use(async (c, next) => {
  return useLogger({
    level: env.LOG_LEVEL,
    format: env.LOG_FORMAT,
    context: {
      appName: "auth-worker",
      deployId: env.CF_VERSION_METADATA.id,
      thread: c.get("traceparent"),
    },
  })(c, next)
})

app.use(hasherMiddleware)
app.route("/", routes)

app.notFound(c => {
  return c.text("Not found", 404)
})

export default app
