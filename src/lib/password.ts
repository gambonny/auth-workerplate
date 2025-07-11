import * as v from "valibot"

import type { OnErrorCallback } from "@types"
import { resetPasswordRecordContract } from "@routes/password/contracts"

const EXPIRATION_SECONDS = 60 * 60 // 1 hour

/**
 * Store a reset‐password token in KV.
 * @returns true on success, false on failure (and calls onError with issues)
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
  } = v.safeParse(resetPasswordRecordContract, { email, token })

  if (!success) {
    onError?.(v.flatten(issues).nested)
    return false
  }

  try {
    await env.OTP_STORE.put(resetTokenKey(token), JSON.stringify(record), {
      expirationTtl: EXPIRATION_SECONDS,
    })
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e)
    onError?.({ kv: [msg] })
    return false
  }

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
  } = v.safeParse(resetPasswordRecordContract, raw)

  if (!success) {
    await env.OTP_STORE.delete(key)
    onError?.(v.flatten(issues).nested)
    return false
  }

  await env.OTP_STORE.delete(key)
  return record.email
}

/**
 * Remove a reset token manually (if needed).
 * @returns true on success, false on failure (and calls onError)
 */
export async function removeToken(
  env: Cloudflare.Env,
  token: string,
  onError?: OnErrorCallback,
): Promise<boolean> {
  try {
    await env.OTP_STORE.delete(resetTokenKey(token))
    return true
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e)
    onError?.({ kv: [msg] })
    return false
  }
}

function resetTokenKey(token: string) {
  return `reset:${token.trim().toLowerCase()}`
}
