import type { Context, Next } from "hono"
import { backOff, type BackoffOptions } from "exponential-backoff"

export function backoffMiddleware(defaultOptions: BackoffOptions) {
  return async (c: Context, next: Next) => {
    c.set(
      "backOff",
      <T>(fn: () => Promise<T>, opts?: BackoffOptions): Promise<T> => {
        return backOff(fn, { ...defaultOptions, ...opts })
      },
    )

    await next()
  }
}

export type BackoffFn = <T>(
  fn: () => Promise<T>,
  opts?: BackoffOptions,
) => Promise<T>
