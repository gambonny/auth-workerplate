import type { InferOutput } from "valibot"
import type {
	ResponseErrorContract,
	ResponseResult,
	ResponseSuccessContract,
} from "./contracts"

export type SignupWorkflowEnv = {
	THIS_WORKFLOW: Workflow
	RESEND: string
	DB: D1Database
}

export type SignupWorkflowParams = {
	email: string
	otp: string
}

export type IResponseSuccess = InferOutput<typeof ResponseSuccessContract>
export type IResponseError = InferOutput<typeof ResponseErrorContract>
export type IResponseResult = InferOutput<typeof ResponseResult>
