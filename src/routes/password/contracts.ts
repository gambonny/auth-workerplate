import * as v from "valibot"
import { emailField, passwordField } from "@auth/contracts"

const tokenField = v.pipe(v.string(), v.trim(), v.minLength(10))

export const forgotPasswordContract = v.object({
  email: emailField,
})

export const resetPasswordRecordContract = v.object({
  token: tokenField,
  email: emailField,
})

export const resetPasswordRouteParamsContract = v.object({
  token: tokenField,
  password: passwordField,
})
