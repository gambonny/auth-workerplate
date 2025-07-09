import * as v from "valibot"

export const emailContract = v.pipe(v.string(), v.email())

export const signupContract = v.object({
  email: emailContract,
  password: v.pipe(
    v.string(),
    v.minLength(8, "Password must be at least 8 characters long"),
  ),
})

export const userPayloadContract = v.object({
  id: v.string(),
  email: emailContract,
  exp: v.number(),
})

// Types
export type UserPayload = v.InferOutput<typeof userPayloadContract>
