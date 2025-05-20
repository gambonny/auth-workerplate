import { env } from "cloudflare:workers"
import { Hono } from "hono"
import { type GetLoggerFn, useLogger } from "@gambonny/cflo"

const app = new Hono<{
	Bindings: CloudflareBindings
	Variables: { getLogger: GetLoggerFn }
}>()
app.use(
	useLogger({
		level: env.LOG_LEVEL,
		format: env.LOG_FORMAT,
		context: {
			appName: "auth-worker",
			deployId: env.CF_VERSION_METADATA.id,
		},
	}),
)

app.post("/signup", c => {
	const logger = c.var.getLogger({ route: "auth.signup" })

	logger.info("signup:started", {
		scope: "user.init",
		event: "signup.started",
	})

	return c.text("Hello Hono!")
})

export default app
