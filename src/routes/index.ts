import { Hono } from "hono"

import { signupRoute } from "./auth/signup"
import { meRoute } from "./auth/me"
import { logoutRoute } from "./auth/logout"
import { refreshRoute } from "./auth/refresh"
import { verifyOtpRoute } from "./otp/verify"
import { passwordForgotRoute } from "./password/forgot"

export const routes = new Hono()

routes.route("/", signupRoute)
routes.route("/", meRoute)
routes.route("/", logoutRoute)
routes.route("/", refreshRoute)
routes.route("/", verifyOtpRoute)
routes.route("/", passwordForgotRoute)

export default routes
