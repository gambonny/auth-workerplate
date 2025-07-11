import * as v from "valibot"
import { emailField, passwordField } from "@auth/contracts"

const tokenField = v.pipe(v.string(), v.trim(), v.minLength(10))

export const forgotPasswordPayloadContract = v.object({
  email: emailField,
})

export const resetPasswordPayloadContract = v.object({
  token: tokenField,
  password: passwordField,
})

export const resetPasswordRecordContract = v.object({
  token: tokenField,
  email: emailField,
})

export type ForgotPasswordPayload = v.InferOutput<
  typeof forgotPasswordPayloadContract
>

export type ResetPasswordPayload = v.InferOutput<
  typeof resetPasswordPayloadContract
>
