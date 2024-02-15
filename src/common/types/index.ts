import { JWA_ALGS } from "common/constants";
import { W3CVerifiableCredentialFormats, W3CVerifiablePresentationFormats } from "common/formats";

// RFC 6749 Section 3.1.1
// OAuth 2.0 Multiple Response Type Encoding Practices Section 3
// OID4VP Section 5.4
// TODO: Maybe we should not give support for the "token" response type
export type AuthzResponseType = "code" | "token" | "id_token" | "vp_token";
export type GrantType = "authorization_code" | "pre-authorised_code" | "vp_token";
export type ControlProofType = "jwt";
export type VpFormatsSupported = {
  [key in W3CVerifiableCredentialFormats | W3CVerifiablePresentationFormats]?: { alg_values_supported: JWA_ALGS[]; };
};
export type CompactVc = string;

export type VerificationResult = { valid: boolean, error?: string };
