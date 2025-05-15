import { Hono } from "hono"
import { createLogger } from "@gambonny/cflo"

const logger = createLogger({
	level: "info",
	format: "pretty",
})

const app = new Hono<{ Bindings: CloudflareBindings }>()

app.post("/signup", c => {
	logger.debug("This log should not appear.")
	return c.text("Hello Hono!")
})

export default app
