import { Hono } from "hono"
import { cors } from "hono/cors"
import { uaBlocker } from "@hono/ua-blocker"
import { aiBots, useAiRobotsTxt } from "@hono/ua-blocker/ai-bots"
import { trimTrailingSlash } from "hono/trailing-slash"
import { contextStorage } from "hono/context-storage"

import { env } from "cloudflare:workers"
import { useLogger } from "@gambonny/cflo"

import routes from "@/routes"
import responderMiddleware from "@/middlewares/responder"
import hasherMiddleware from "@/middlewares/hasher"
import { backoffMiddleware } from "@/middlewares/backoff"
import type { AppEnv } from "@types"
import traceparent from "@/middlewares/traceparent"

const app = new Hono<AppEnv>()

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
app.use(traceparent)

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
export { SignupWorkflow } from "@/workflows/signup"
