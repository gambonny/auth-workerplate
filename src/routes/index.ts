import { Hono } from "hono"

import { signupRoute } from "./auth/signup"

export const routes = new Hono()

routes.route("/", signupRoute)

export default routes
