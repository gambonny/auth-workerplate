import * as v from "valibot"
import { emailContract } from "@routes/auth/contracts"

export const otpContract = v.pipe(v.string(), v.length(8))

export const verifyOtpRoutePayloadContract = v.object({
  email: emailContract,
  otp: otpContract,
})

export const otpRecordContract = v.object({
  otp: otpContract,
  attempts: v.pipe(
    v.number(),
    v.minValue(0),
    v.maxValue(2, "too many attempts"),
  ),
})
