import * as v from "valibot"

export const signupContract = v.object({
  email: v.pipe(v.string(), v.email()),
  password: v.pipe(
    v.string(),
    v.minLength(8, "Password must be at least 8 characters long"),
  ),
})

export const BaseResponseContract = v.object({
  status: v.union([v.literal("success"), v.literal("error")]),
  message: v.string(),
  resource_url: v.optional(v.string()),
})

export const ResponseSuccessContract = v.intersect([
  BaseResponseContract,
  v.object({
    status: v.literal("success"),
    data: v.optional(v.unknown()),
  }),
])

export const ResponseErrorContract = v.intersect([
  BaseResponseContract,
  v.object({
    status: v.literal("error"),
    issues: v.optional(
      v.record(v.string(), v.undefinedable(v.array(v.string()))),
    ),
  }),
])

export const ResponseResult = v.union([
  ResponseSuccessContract,
  ResponseErrorContract,
])

export const otpContract = v.object({
  email: v.pipe(v.string(), v.email()),
  otp: v.pipe(v.string(), v.minLength(6)),
})
