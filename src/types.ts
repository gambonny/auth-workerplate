import type { UnknownRecord } from "type-fest"

export type SignupWorkflowEnv = {
	THIS_WORKFLOW: Workflow
	RESEND: string
	DB: D1Database
}

export type SignupWorkflowParams = {
	email: string
	otp: string
}

export type SuccessResponse<T extends object = UnknownRecord> = {
	status: "success"
	data: T
}

export type ErrorResponse = {
	status: "error"
	error: string
	issues?: Record<string, string[] | undefined>
}
