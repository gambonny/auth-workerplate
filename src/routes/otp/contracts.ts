import * as v from "valibot"
import { emailContract } from "@routes/auth/contracts"

export const otpContract = v.pipe(v.string(), v.length(8))
export const verifyOtpContract = v.object({
  email: emailContract,
  otp: otpContract,
})
