import * as v from "valibot"

export default v.object({
  otp: v.pipe(v.string(), v.length(8)),
  attempts: v.pipe(v.number(), v.minValue(0)),
})
