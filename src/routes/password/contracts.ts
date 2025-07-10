import * as v from "valibot"
import { emailContract } from "@routes/auth/contracts"

export const resetPasswordContract = v.object({
  email: emailContract,
})
