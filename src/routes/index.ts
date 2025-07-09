import { Hono } from "hono"

import { signupRoute } from "./auth/signup"
import { refreshRoute } from "./auth/refresh"
import { otpRoute } from "./otp/verify"

export const routes = new Hono()

routes.route("/", signupRoute)
routes.route("/", refreshRoute)
routes.route("/", otpRoute)

export default routes
