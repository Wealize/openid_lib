import { generateChallenge as pkceGenerate } from "pkce-challenge"
import { generateRandomString } from "./string.utils.js"
import { DEFAULT_PKCE_LENGTH } from "../constants/index.js"

export async function generateChallenge(code_verifier?: string) {
  if (!code_verifier) {
    code_verifier = generateRandomString(DEFAULT_PKCE_LENGTH)
  }
  return await pkceGenerate(code_verifier)
}
