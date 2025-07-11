import * as v from "valibot"

export const emailField = v.pipe(
  v.string(),
  v.trim(),
  v.nonEmpty("Email is required"),
  v.email(),
)

export const passwordField = v.pipe(
  v.string(),
  v.minLength(8, "Password must be at least 8 characters long"),
)

export const signupPayloadContract = v.object({
  email: emailField,
  password: passwordField,
})

export const loginContract = v.object({
  email: emailField,
  password: passwordField,
})

export const userPayloadContract = v.object({
  id: v.string(),
  email: emailField,
  exp: v.number(),
})

export type SignupPayload = v.InferOutput<typeof signupPayloadContract>
export type UserPayload = v.InferOutput<typeof userPayloadContract>
