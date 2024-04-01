export const ID_TOKEN_REQUEST_DEFAULT_EXPIRATION_TIME = 10 * 60 * 1000; // 10 minute in ms
export const VP_TOKEN_REQUEST_DEFAULT_EXPIRATION_TIME = 10 * 60 * 1000; // 10 minute in ms
export const C_NONCE_EXPIRATION_TIME = 1 * 3600 // 1 hour in seconds
export const ACCESS_TOKEN_EXPIRATION_TIME = 1 * 3600 // 1 hour in seconds
export const DEFAULT_PKCE_LENGTH = 7;
export const DEFAULT_SCOPE = "openid";
export const OPENID_CREDENTIAL_AUTHZ_DETAILS_TYPE = "openid_credential";
export const W3C_VP_TYPE = "VerifiablePresentation";
export const CONTEXT_VC_DATA_MODEL_1 = ["https://www.w3.org/2018/credentials/v1"];
export const CONTEXT_VC_DATA_MODEL_2 = ["https://www.w3.org/ns/credentials/v2"];
export type JWA_ALGS =
  "HS256" | "HS384" | "HS512" | "RS256" | "RS384" | "RS512" | "ES256" |
  "ES384" | "ES512" | "PS256" | "PS384" | "PS512" | "none" | "ES256K";