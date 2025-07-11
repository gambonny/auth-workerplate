import * as v from "valibot"
import { emailField } from "@auth/schemas"

export const otpCodeField = v.pipe(v.string(), v.length(8))

export const otpPayloadSchema = v.object({
  email: emailField,
  otp: otpCodeField,
})

export const otpRecordSchema = v.object({
  otp: otpCodeField,
  attempts: v.pipe(
    v.number(),
    v.minValue(0),
    v.maxValue(2, "too many attempts"),
  ),
})

export type OtpPayload = v.InferOutput<typeof otpPayloadSchema>
