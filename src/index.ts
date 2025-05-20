import { env } from "cloudflare:workers"
import * as v from "valibot"
import { validator } from "hono/validator"
import { Hono } from "hono"
import { type GetLoggerFn, useLogger } from "@gambonny/cflo"
import { requireThread } from "./middlewares"
import { signupContract } from "./contracts"

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

app.post(
	"/signup",
	validator("form", async (body, c) => {
		const validation = v.safeParse(signupContract, body)

		if (validation.success) {
			return validation.output
		}

		const logger = c.var.getLogger({ route: "auth.signup.validator" })

		logger.warn("signup:validation:failed", {
			event: "validation.failed",
			scope: "validator.schema",
			input: validation.output,
			issues: v.flatten(validation.issues).nested,
		})

		return c.json({ status: "error", error: "Invalid input" }, 400)
	}),
	c => {
		const { email } = c.req.valid("form")
		const logger = c.var.getLogger({ route: "auth.signup.handler" })

		logger.info("signup:started", {
			event: "handler.started",
			scope: "handler.init",
			input: { email },
		})

		return c.text("Hello Hono!")
	},
)

export default app
