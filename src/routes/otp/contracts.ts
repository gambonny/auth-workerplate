import * as v from "valibot"

export const otpContract = v.object({
  email: v.pipe(v.string(), v.email()),
  otp: v.pipe(v.string(), v.minLength(6)),
})
