import { Hono } from "hono"

const app = new Hono<{ Bindings: CloudflareBindings }>()

app.post("/signup", c => {
	return c.text("Hello Hono!")
})

export default app
