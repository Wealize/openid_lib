import { JWA_ALGS } from "common/constants";
import { W3CVerifiableCredentialFormats, W3CVerifiablePresentationFormats } from "common/formats";

export type AuthzResponseType = "code" | "token"; // RFC 6749 Section 3.1.1
// export type VpFormatsSupported = { // W3C FORMATS
//   jwt_vp: {
//     alg_values_supported: JWA_ALGS[]
//   },
//   jwt_vc: {
//     alg_values_supported: JWA_ALGS[]
//   }
// };

export type VpFormatsSupported = {
  [key in W3CVerifiableCredentialFormats | W3CVerifiablePresentationFormats]?: { alg_values_supported: JWA_ALGS[]; };
};
