import * as v from "valibot"
import { emailContract, passwordContract } from "@routes/auth/contracts"

export const forgotPasswordContract = v.object({
  email: emailContract,
})

export const resetPasswordRecordContract = v.object({
  token: v.string(),
  email: emailContract,
})

export const resetPasswordRouteParamsContract = v.object({
  token: v.string(),
  password: passwordContract,
})
