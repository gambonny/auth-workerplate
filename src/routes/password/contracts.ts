import * as v from "valibot"
import { emailContract } from "@routes/auth/contracts"

export const forgotPasswordContract = v.object({
  email: emailContract,
})

export const resetPasswordContract = v.object({
  token: v.string(),
  email: emailContract,
})
