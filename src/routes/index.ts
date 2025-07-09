import { Hono } from "hono"

import { signupRoute } from "./auth/signup"
import { otpRoute } from "./otp/verify"

export const routes = new Hono()

routes.route("/", signupRoute)
routes.route("/", otpRoute)

export default routes
