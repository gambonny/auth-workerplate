import type { IResponseSuccess, IResponseError } from "./types"
import { getContext } from "hono/context-storage"

export async function hashPassword(password: string, salt: string) {
  const encoder = new TextEncoder()
  const passwordData = encoder.encode(password)
  const saltData = encoder.encode(salt)

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    passwordData,
    { name: "PBKDF2" },
    false,
    ["deriveBits"],
  )

  const hashBuffer = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltData,
      iterations: 60000,
      hash: "SHA-256",
    },
    keyMaterial,
    256,
  )

  const hashArray = Array.from(new Uint8Array(hashBuffer))
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, "0")).join("")
  return hashHex
}

export function salt(length = 16) {
  const array = new Uint8Array(length)
  crypto.getRandomValues(array)
  return Array.from(array, b => b.toString(16).padStart(2, "0")).join("")
}

export function generateOtp(): string {
  return Math.floor(Math.random() * 100_000_000)
    .toString()
    .padStart(8, "0")
}

export const withSuccess = <T extends object>(
  message: string,
  data?: T,
): IResponseSuccess => {
  const c = getContext()
  const { origin, pathname } = new URL(c.req.url)

  return {
    status: "success",
    message,
    resource_url: origin + pathname,
    ...(data && Object.keys(data).length ? { data } : {}),
  }
}

export const withError = (
  message: string,
  issues?: Record<string, string[] | undefined> | undefined,
): IResponseError => {
  const c = getContext()
  const { origin, pathname } = new URL(c.req.url)

  return {
    status: "error",
    message,
    resource_url: origin + pathname,
    issues,
  }
}

export async function sha256hex(text: string): Promise<string> {
  const data = new TextEncoder().encode(text)
  const hash = await crypto.subtle.digest("SHA-256", data)
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("")
}
