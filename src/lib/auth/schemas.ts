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

export const signupPayloadSchema = v.object({
  email: emailField,
  password: passwordField,
})

export const loginPayloadSchema = v.object({
  email: emailField,
  password: passwordField,
})

export const userPayloadSchema = v.object({
  id: v.string(),
  email: emailField,
  exp: v.number(),
})

export type SignupPayload = v.InferOutput<typeof signupPayloadSchema>
export type LoginPayload = v.InferOutput<typeof loginPayloadSchema>
export type UserPayload = v.InferOutput<typeof userPayloadSchema>
