import { Hono } from "hono"
import { type GetLoggerFn, useLogger } from "@gambonny/cflo"

const app = new Hono<{
	Bindings: CloudflareBindings
	Variables: { getLogger: GetLoggerFn }
}>()
app.use(
	useLogger({
		level: "info",
		format: "json",
		context: {
			appName: "auth-worker",
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
