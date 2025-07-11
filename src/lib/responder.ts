import { getContext } from "hono/context-storage"
import type { ContentfulStatusCode } from "hono/utils/http-status"
import type { ValidationIssues } from "@types"

interface SuccessPayload<T> {
  status: "success"
  message: string
  resource_url: string
  data?: T
}

interface ErrorPayload {
  status: "error"
  message: string
  resource_url: string
  issues?: ValidationIssues
}

export type Responder = ReturnType<typeof makeResponder>

function isSuccess<T>(
  type: "success" | "error",
  dataOrIssues: T | ValidationIssues,
): dataOrIssues is T {
  return type === "success"
}

function buildPayload<T>(
  type: "success",
  message: string,
  data?: T,
): SuccessPayload<T>

function buildPayload(
  type: "error",
  message: string,
  issues?: ValidationIssues,
): ErrorPayload

function buildPayload<T>(
  type: "success" | "error",
  message: string,
  dataOrIssues?: T | ValidationIssues,
): SuccessPayload<T> | ErrorPayload {
  const c = getContext()
  const { origin, pathname } = new URL(c.req.url)
  const base = { status: type, message, resource_url: origin + pathname }

  if (isSuccess(type, dataOrIssues)) {
    return {
      ...base,
      ...(dataOrIssues && Object.keys(dataOrIssues).length > 0
        ? { data: dataOrIssues }
        : {}),
    }
  }

  return {
    ...base,
    issues: dataOrIssues,
  }
}

export default function makeResponder() {
  const c = getContext()

  return {
    success<T>(msg: string, data?: T, statusCode: ContentfulStatusCode = 200) {
      const payload = buildPayload("success", msg, data)
      return c.json(payload, statusCode)
    },
    error(
      msg: string,
      issues?: ValidationIssues,
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
