import { Temporal } from "@js-temporal/polyfill"

const MAX_OTP_ATTEMPTS = 2

export function generateOtp(): string {
  return Math.floor(Math.random() * 100_000_000)
    .toString()
    .padStart(8, "0")
}

export async function storeOtp(
  env: Cloudflare.Env,
  email: string,
  otp: string,
) {
  const key = `otp:${email.trim().toLowerCase()}`
  const value = JSON.stringify({ otp, attempts: 0 })

  await env.OTP_STORE.put(key, value, {
    expiration:
      Temporal.Now.instant().add({ hours: 1 }).epochMilliseconds / 1000,
  })
}

export async function verifyOtp(
  env: Cloudflare.Env,
  email: string,
  submitted: string,
) {
  const key = `otp:${email.trim().toLowerCase()}`
  const record = (await env.OTP_STORE.get(key, "json")) as {
    otp: string
    attempts: number
  }

  if (!record || !record.otp) {
    await env.OTP_STORE.delete(key)
    return { ok: false as const, reason: "expired" }
  }

  // 1) enforce max-attempts
  if (record.attempts > MAX_OTP_ATTEMPTS) {
    await env.OTP_STORE.delete(key)
    return { ok: false as const, reason: "too_many" }
  }

  // 2) check the code
  if (record.otp !== submitted) {
    record.attempts++
    await env.OTP_STORE.put(key, JSON.stringify(record))
    return { ok: false as const, reason: "invalid" }
  }

  // 3) success! remove the key so it can’t be reused
  await env.OTP_STORE.delete(key)
  return { ok: true as const }
}
