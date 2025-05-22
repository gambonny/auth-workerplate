import { Resend } from "resend"

import {
	WorkflowEntrypoint,
	type WorkflowStep,
	type WorkflowEvent,
} from "cloudflare:workers"

type Env = {
	THIS_WORKFLOW: Workflow
	RESEND: string
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
			const resend = new Resend(this.env.RESEND)
			try {
				resend.emails.send({
					from: "send@gambonny.com",
					to: email,
					subject: "Your one-time password",
					html: `<p>Your OTP is <strong>${otp}</strong></p>`,
				})
			} catch (e) {
				console.info(String(e))
			}
		})

		// Step 2: Wait for 1 hour
		await step.sleep("wait-for-activation", "1 hour")
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
