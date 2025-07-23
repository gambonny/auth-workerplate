import { WorkflowEntrypoint } from "cloudflare:workers"
import type { WorkflowEvent, WorkflowStep } from "cloudflare:workers"
import { Resend } from "resend"

type SignupWorkflowEnv = {
  THIS_WORKFLOW: Workflow
  RESEND: string
  DB: D1Database
}

type SignupWorkflowParams = {
  email: string
  otp: string
}

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
