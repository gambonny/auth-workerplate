import * as v from "valibot"
import { emailField, passwordField } from "@auth/schemas"

const tokenField = v.pipe(v.string(), v.trim(), v.minLength(10))

export const forgotPasswordPayloadSchema = v.object({
  email: emailField,
})

export const resetPasswordPayloadSchema = v.object({
  token: tokenField,
  password: passwordField,
})

export const resetPasswordRecordSchema = v.object({
  token: tokenField,
  email: emailField,
})

export type ForgotPasswordPayload = v.InferOutput<
  typeof forgotPasswordPayloadSchema
>

export type ResetPasswordPayload = v.InferOutput<
  typeof resetPasswordPayloadSchema
>
