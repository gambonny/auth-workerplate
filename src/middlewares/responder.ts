import { createMiddleware } from "hono/factory"
import makeResponder from "@/lib/responder"

const responderMiddleware = createMiddleware(async (c, next) => {
  c.set("responder", makeResponder())
  await next()
})

export default responderMiddleware
