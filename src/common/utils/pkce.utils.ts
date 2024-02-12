import { generateChallenge as pkceGenerate } from "pkce-challenge"
import { generateRandomString } from "./string.utils"
import { DEFAULT_PKCE_LENGTH } from "common/constants"

export function generateChallenge(code_verifier?: string) {
  if (!code_verifier) {
    code_verifier = generateRandomString(DEFAULT_PKCE_LENGTH)
  }
  return pkceGenerate(code_verifier)
}
