import * as v from "valibot"

export const signupContract = v.object({
  email: v.pipe(v.string(), v.email()),
  password: v.pipe(
    v.string(),
    v.minLength(8, "Password must be at least 8 characters long"),
  ),
})
