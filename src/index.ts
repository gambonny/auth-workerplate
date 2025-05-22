import { env } from "cloudflare:workers"
import { type GetLoggerFn, useLogger } from "@gambonny/cflo"
import { Hono } from "hono"
import { validator } from "hono/validator"
import * as v from "valibot"
import { signupContract } from "./contracts"
import { generateOtp, hashPassword, salt } from "./generator"
import { requireThread } from "./middlewares"

import {
	WorkflowEntrypoint,
	type WorkflowEvent,
	type WorkflowStep,
} from "cloudflare:workers"
import { Resend } from "resend"
import type {
	ErrorResponse,
	SignupWorkflowEnv,
	SignupWorkflowParams,
	SuccessResponse,
} from "./types"

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
				try {
					await resend.emails.send({
						from: "send@gambonny.com",
						to: email,
						subject: "Your one-time password",
						html: `<p>Your OTP is <strong>${otp}</strong></p>`,
					})
				} catch (e) {
					console.error(String(e))
				}
			},
		)

		// Step 2: Wait for 1 minute
		await step.sleep("wait-for-activation", "1 minute")

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

		return c.json(
			{
				status: "error",
				error: "Invalid input",
				issues: v.flatten(validation.issues).nested,
			} satisfies ErrorResponse,
			400,
		)
	}),
	async (c): Promise<Response> => {
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
				"INSERT INTO users (email, password_hash, salt, otp) VALUES (?, ?, ?, ?)",
			)
				.bind(email, passwordHash, generatedSalt, otp)
				.run()

			logger.info("user:registered", {
				event: "db.insert.success",
				scope: "db.users",
				input: { email },
			})

			const workflow = await c.env.SIGNUP_WFW.create({ params: { email, otp } })

			logger.debug("workflow:created", {
				event: "workflow.created",
				scope: "db.users",
				workflow,
			})

			return c.json(
				{
					status: "success",
					data: {
						message: "User registered, email with otp has been sent",
					},
				} satisfies SuccessResponse,
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

					return c.json(
						{
							status: "error",
							error: "Invalid input",
							issues: { email: ["User already exists"] },
						} satisfies ErrorResponse,
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

			return c.json(
				{ status: "error", error: errorMessage } satisfies ErrorResponse,
				500,
			)
		}
	},
)
export default app
