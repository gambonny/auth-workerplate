import * as v from "valibot"

export const signupContract = v.object({
  email: v.pipe(v.string(), v.email()),
  password: v.pipe(
    v.string(),
    v.minLength(8, "Password must be at least 8 characters long"),
  ),
})

export const ResponseSuccessContract = v.object({
  status: v.literal("success"),
  data: v.objectWithRest(
    {
      message: v.string(),
    },
    v.unknown(),
  ),
})

export const ResponseErrorContract = v.object({
  status: v.literal("error"),
  error: v.string(),
  issues: v.optional(
    v.record(v.string(), v.undefinedable(v.array(v.string()))),
  ),
})

export const ResponseResult = v.union([
  ResponseSuccessContract,
  ResponseErrorContract,
])
