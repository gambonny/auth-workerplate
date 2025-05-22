import { Resend } from "resend"

import {
	WorkflowEntrypoint,
	type WorkflowStep,
	type WorkflowEvent,
} from "cloudflare:workers"

import { env } from "cloudflare:workers"
import * as v from "valibot"
import { validator } from "hono/validator"
import { Hono } from "hono"
import { type GetLoggerFn, useLogger } from "@gambonny/cflo"
import { requireThread } from "./middlewares"
import { signupContract } from "./contracts"
import { generateOtp, hashPassword, salt } from "./generator"

type Env = {
	THIS_WORKFLOW: Workflow
}

type Params = {
	email: string
	otp: string
	createdAt: string
}

export class SignupWorkflow extends WorkflowEntrypoint<Env, Params> {
	async run(event: WorkflowEvent<Params>, step: WorkflowStep) {
		const { email, otp } = event.payload

		// Step 1: Send OTP email
		await step.do("send-otp-email", async () => {
			const resend = new Resend(await env.RESEND.get())
			resend.emails.send({
				from: "gambonny@gmail.com",
				to: email,
				subject: "Your one-time password",
				html: `<p>Your OTP is <strong>${otp}</strong></p>`,
			})
		})

		// // Step 2: Wait for 1 hour
		// await step.sleep("wait-for-activation", "1 hour")
		//
		// // Step 3: Check if user is activated
		// const isActivated = await step.do("check-activation", async () => {
		// 	// Implement activation check logic
		// 	return false // Replace with actual check
		// })
		//
		// if (!isActivated) {
		// 	// Step 4: Delete unactivated user
		// 	await step.do("delete-user", async () => {
		// 		// Implement user deletion logic
		// 	})
		// } else {
		// 	// Step 5: Send welcome email
		// 	await step.do("send-welcome-email", async () => {
		// 		// Implement welcome email logic
		// 	})
		// }
	}
}

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
	async c => {
		const { email, password } = c.req.valid("form")
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

			await c.env.DB.prepare(
				" INSERT INTO users (email, password_hash, salt, otp) VALUES (?, ?, ?, ?)",
			)
				.bind(email, passwordHash, generatedSalt, otp)
				.run()

			logger.info("user:registered", {
				event: "db.insert.success",
				scope: "db.users",
				input: { email },
			})

			await c.env.SIGNUP_WFW.create({
				email,
				otp,
				createdAt: new Date().toISOString(),
			})

			return c.json(
				{ message: "User registered, email with otp has been sent" },
				201,
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

					return c.json({ error: "User already exists" }, 409)
				}
			}

			const errorMessage = err instanceof Error ? err.message : String(err)

			logger.error("user:registration:error", {
				event: "signup.error",
				scope: "db.users",
				error: errorMessage,
			})

			return c.json({ error: errorMessage }, 500)
		}
	},
)

export default app
