import { sha256 } from "@noble/hashes/sha2"
import { bytesToHex } from "@noble/hashes/utils"

export function makeHasher(pepper: string) {
  return (input: string) =>
    bytesToHex(sha256(`${pepper}:${input.trim().toLowerCase()}`))
}
