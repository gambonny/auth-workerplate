import { Temporal } from "@js-temporal/polyfill"

const MAX_OTP_ATTEMPTS = 1

export async function storeOtp(
  env: Cloudflare.Env,
  email: string,
  otp: string,
) {
  const key = `otp:${email.trim().toLowerCase()}`
  const value = JSON.stringify({ otp, attempts: 0 })
  const expiration = Temporal.Now.instant().add({ hours: 1 }).epochMilliseconds
  console.info("expiration: ", expiration)
  console.info("key: ", key)
  await env.OTP_STORE.put(key, value, {
    expiration,
  })
}

export async function verifyOtp(
  env: Cloudflare.Env,
  email: string,
  submitted: string,
) {
  const key = `otp:${email.trim().toLowerCase()}`
  const raw = await env.OTP_STORE.get(key)
  if (!raw) {
    // either never generated or already expired
    return { ok: false as const, reason: "expired" }
  }

  let record: { otp: string; attempts: number }
  try {
    record = JSON.parse(raw)
  } catch {
    // corrupt data — treat as expired
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
