import { createMiddleware } from "hono/factory"
import { makeHasher } from "@lib/hash"
import type { AppEnv } from "@types"

const hasherMiddleware = createMiddleware<AppEnv>(async (c, next) => {
  const pepper = c.env.HASH_PEPPER

  if (!pepper) {
    console.error("HASH_PEPPER env var missing")
    return c.text("Internal error", 500)
  }

  c.set("hash", makeHasher(pepper))
  await next()
})

export default hasherMiddleware
