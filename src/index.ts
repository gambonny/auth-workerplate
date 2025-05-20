import { env } from "cloudflare:workers"
import { Hono } from "hono"
import { type GetLoggerFn, useLogger } from "@gambonny/cflo"
import { requireThread } from "./middlewares/thread"

const app = new Hono<{
	Bindings: CloudflareBindings
	Variables: { thread: string; getLogger: GetLoggerFn }
}>()
app.use(requireThread)

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

app.post("/signup", c => {
	const logger = c.var.getLogger({ route: "auth.signup" })

	logger.info("signup:started", {
		scope: "user.init",
		event: "signup.started",
	})

	return c.text("Hello Hono!")
})

export default app
