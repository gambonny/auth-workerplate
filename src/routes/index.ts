import { Hono } from "hono"

import { signupRoute } from "./auth/signup"
import { loginRoute } from "./auth/login"
import { meRoute } from "./auth/me"
import { logoutRoute } from "./auth/logout"
import { refreshRoute } from "./auth/refresh"
import { verifyOtpRoute } from "./otp/verify"
import { passwordForgotRoute } from "./password/forgot"
import { passwordResetRoute } from "./password/reset"

export const routes = new Hono()

routes.route("/", signupRoute)
routes.route("/", loginRoute)
routes.route("/", meRoute)
routes.route("/", logoutRoute)
routes.route("/", refreshRoute)
routes.route("/", verifyOtpRoute)
routes.route("/", passwordForgotRoute)
routes.route("/", passwordResetRoute)

export default routes
