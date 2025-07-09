import * as v from "valibot"
import { otpContract } from "@routes/otp/contracts"

export default v.object({
  otp: otpContract,
  attempts: v.pipe(v.number(), v.minValue(0)),
})
