import type { Context } from "hono"
import { setCookie } from "hono/cookie"
import type { AppEnv } from "@types"

type Ctx = Context<AppEnv>

const baseOptions = {
  httpOnly: true,
  secure: true,
  sameSite: "None" as const,
  path: "/",
}

export function setSecureCookie(
  c: Ctx,
  name: string,
  value: string,
  maxAge: number,
) {
  setCookie(c, name, value, { ...baseOptions, maxAge })
}

/** Issue both auth cookies in one call */
export function issueAuthCookies(
  c: Ctx,
  accessToken: string,
  refreshToken: string,
  {
    accessTtl = 60 * 60, // 1 h
    refreshTtl = 60 * 60 * 24 * 14, // 14 d
  } = {},
) {
  setSecureCookie(c, "token", accessToken, accessTtl)
  setSecureCookie(c, "refresh_token", refreshToken, refreshTtl)
}

/** Clear both auth cookies (logout) */
export function clearAuthCookies(c: Ctx) {
  setSecureCookie(c, "token", "", 0)
  setSecureCookie(c, "refresh_token", "", 0)
}
