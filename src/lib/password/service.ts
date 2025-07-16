import * as v from "valibot"

import { resetPasswordRecordSchema } from "./schemas"
import type { OnErrorCallback } from "@types"

const EXPIRATION_SECONDS = 60 * 60 // 1 hour

/**
 * Store a reset‐password token in KV.
 * Let KV errors bubble so the route’s backoff can catch/retry them.
 */
export async function storeToken(
  env: Cloudflare.Env,
  email: string,
  token: string,
  onError?: OnErrorCallback,
): Promise<boolean> {
  const {
    success,
    output: record,
    issues,
  } = v.safeParse(resetPasswordRecordSchema, { token, email })

  if (!success) {
    onError?.(v.flatten(issues).nested)
    return false
  }

  await env.OTP_STORE.put(resetTokenKey(token), JSON.stringify(record), {
    expirationTtl: EXPIRATION_SECONDS,
  })

  return true
}

/**
 * Verify a reset‐password token.
 * @returns the email if valid, or false on expiration/invalid (and calls onError)
 */
export async function verifyToken(
  env: Cloudflare.Env,
  submitted: string,
  onError?: OnErrorCallback,
): Promise<string | false> {
  const key = resetTokenKey(submitted)
  const raw = await env.OTP_STORE.get(key, "json")

  const {
    success,
    output: record,
    issues,
  } = v.safeParse(resetPasswordRecordSchema, raw)

  if (!success) {
    onError?.(v.flatten(issues).nested)
    await env.OTP_STORE.delete(key)
    return false
  }

  await env.OTP_STORE.delete(key)
  return record.email
}

export function resetTokenKey(token: string) {
  return `reset:${token.trim().toLowerCase()}`
}
