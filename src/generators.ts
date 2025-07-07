import type { ContentfulStatusCode } from "hono/utils/http-status"
import type { ErrorPayload, SuccessPayload } from "./types"
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

export function makeResponder() {
  const c = getContext()

  return {
    success<T>(msg: string, data?: T, statusCode: ContentfulStatusCode = 200) {
      const payload = buildPayload("success", msg, data)
      return c.json(payload, statusCode)
    },
    error(
      msg: string,
      issues?: Record<string, string[] | undefined> | undefined,
      statusCode: ContentfulStatusCode = 400,
    ) {
      const payload = buildPayload("error", msg, issues)
      return c.json(payload, statusCode)
    },
    created<T>(msg: string, data?: T) {
      return this.success(msg, data, 201)
    },
  }
}

export async function sha256hex(text: string): Promise<string> {
  const data = new TextEncoder().encode(text)
  const hash = await crypto.subtle.digest("SHA-256", data)
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("")
}

function resourceUrl() {
  const { origin, pathname } = new URL(getContext().req.url)
  return origin + pathname
}

export function buildPayload<T>(
  type: "success",
  message: string,
  data?: T,
): SuccessPayload<T>

export function buildPayload(
  type: "error",
  message: string,
  issues?: Record<string, string[] | undefined> | undefined,
): ErrorPayload

export function buildPayload<T>(
  type: "success" | "error",
  message: string,
  dataOrIssues?: T | Record<string, string[] | undefined> | undefined,
): SuccessPayload<T> | ErrorPayload {
  const c = getContext()
  const { origin, pathname } = new URL(c.req.url)
  const base = { status: type, message, resource_url: origin + pathname }

  if (type === "success") {
    return {
      ...base,
      ...(dataOrIssues && Object.keys(dataOrIssues as object).length
        ? { data: dataOrIssues as T }
        : {}),
    }
  }

  return {
    ...base,
    issues: dataOrIssues as Record<string, string[] | undefined> | undefined,
  }
}
