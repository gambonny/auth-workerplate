import { Temporal } from "@js-temporal/polyfill"
import * as v from "valibot"

import { otpRecordSchema } from "./schemas"
import type { OnErrorCallback } from "@types"

export function generateOtp(): string {
  return Math.floor(Math.random() * 100_000_000)
    .toString()
    .padStart(8, "0")
}

export async function storeOtp(
  env: Cloudflare.Env,
  email: string,
  otp: string,
  onError?: OnErrorCallback,
): Promise<boolean> {
  const {
    success,
    issues,
    output: record,
  } = v.safeParse(otpRecordSchema, {
    otp,
    attempts: 0,
  })

  if (!success) {
    onError?.(v.flatten(issues).nested)
    return false
  }

  await env.OTP_STORE.put(otpKey(email), JSON.stringify(record), {
    expiration:
      Temporal.Now.instant().add({ hours: 1 }).epochMilliseconds / 1000,
  })

  return true
}

export async function verifyOtp(
  env: Cloudflare.Env,
  email: string,
  submitted: string,
  onError?: OnErrorCallback,
): Promise<boolean> {
  const key = otpKey(email)
  const {
    success,
    output: record,
    issues,
  } = v.safeParse(otpRecordSchema, await env.OTP_STORE.get(key, "json"))

  if (!success) {
    onError?.(v.flatten(issues).nested)
    await env.OTP_STORE.delete(key)
    return false
  }

  if (record.otp !== submitted) {
    record.attempts++
    onError?.({ otp: [`otp invalid -- attempt #${record.attempts}`] })
    await env.OTP_STORE.put(key, JSON.stringify(record))
    return false
  }

  await env.OTP_STORE.delete(key)
  return true
}

function otpKey(email: string) {
  return `otp:${email.trim().toLowerCase()}`
}
