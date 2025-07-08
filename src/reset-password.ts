import { Temporal } from "@js-temporal/polyfill"

const MAX_OTP_ATTEMPTS = 1

export async function storeToken(
  env: Cloudflare.Env,
  email: string,
  token: string,
) {
  const key = `reset:${token.trim().toLowerCase()}`
  const value = JSON.stringify({ email })

  await env.OTP_STORE.put(key, value, {
    expiration:
      Temporal.Now.instant().add({ hours: 1 }).epochMilliseconds / 1000,
  })
}

export async function verifyToken(env: Cloudflare.Env, submitted: string) {
  const key = `reset:${submitted.trim().toLowerCase()}`
  const raw = await env.OTP_STORE.get(key)
  if (!raw) return false

  let record: { email: string }

  try {
    record = JSON.parse(raw)
  } catch {
    await env.OTP_STORE.delete(key)
    return false
  }

  await env.OTP_STORE.delete(key)
  return record.email
}
