import { VerificationResult } from "../types";

export async function alwaysAcceptVerification(
  ..._data: any[]
): Promise<VerificationResult> {
  return { valid: true }
}
