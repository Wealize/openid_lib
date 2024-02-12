// TODO: "JWT_VC is a old identifier. It's there for compatibility"
export type W3CVerifiableCredentialFormats = "jwt_vc_json" | "jwt_vc_json-ld" | "ldp_vc" | "jwt_vc";
// TODO: "JWT_VP is a old identifier. It's there for compatibility"
export type W3CVerifiablePresentationFormats = "jwt_vp_json" | "ldp_vp" | "jwt_vp";
// OAuth 2.0 Multiple Response Type Encoding Practices
export type AuthzResponseMode = "direct_post" | "post" | "query" | "fragment";