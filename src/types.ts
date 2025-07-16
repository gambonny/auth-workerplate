import type { TimingVariables } from "hono/timing"
import type { UnknownRecord } from "type-fest"
import type { GetLoggerFn } from "@gambonny/cflo"

import type { Responder } from "@/lib/responder"
import type { makeHasher } from "@/lib/hash"
import type { BackoffFn } from "@/middlewares/backoff"

export type SignupWorkflowEnv = {
  THIS_WORKFLOW: Workflow
  RESEND: string
  DB: D1Database
}

export type SignupWorkflowParams = {
  email: string
  otp: string
}

export type AppEnv = {
  Bindings: CloudflareBindings
  Variables: {
    traceparent: string
    getLogger: GetLoggerFn
    responder: Responder
    hash: ReturnType<typeof makeHasher>
    backoff: BackoffFn
  } & TimingVariables
}

export type ValidationIssues = Record<string, string[] | undefined> | undefined
export type OnErrorCallback = (issues: ValidationIssues) => void

export type TokenSentinelService = {
  //TODO: fix
  validateToken: (token: string) => Promise<false | UnknownRecord>
}
