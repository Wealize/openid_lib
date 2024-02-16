import { JWA_ALGS } from "../../common/constants/index.js";
import { AuthzResponseMode } from "../../common/formats/index.js";
import { AuthorizationDetails } from "../../common/interfaces/authz_details.interface.js";
import { HolderMetadata } from "../../common/interfaces/client_metadata.interface.js";
import { VerificationResult, VpFormatsSupported } from "../../common/types/index.js";
import { DIDDocument } from "did-resolver";
import { JwtHeader, JwtPayload } from "jsonwebtoken";

export type TokenSignCallback = (
  payload: JwtPayload,
  supportedSignAlg?: JWA_ALGS[]
) => Promise<string>;

export type IdTokenVerifyCallback = (
  header: JwtHeader,
  payload: JwtPayload,
  didDocument: DIDDocument
) => Promise<VerificationResult>;

export type GetClientDefaultMetada = () => Promise<HolderMetadata>;

export type VerifyBaseAuthzRequestOptionalParams = {
  authzDetailsVerifyCallback?: (authDetails: AuthorizationDetails) => Promise<VerificationResult>;
  scopeVerifyCallback?: (scope: string) => Promise<VerificationResult>;
  issuerStateVerifyCallback?: (state: string) => Promise<VerificationResult>;
};

export interface GenerateAccessTokenOptionalParameters {
  authorizeCodeCallback?: (
    clientId: string,
    code: string
  ) => Promise<VerificationResult>;
  preAuthorizeCodeCallback?: (
    clientId: string,
    preCode: string,
    pin?: string
  ) => Promise<VerificationResult>;
  codeVerifierCallback?: (
    clientId: string,
    codeVerifier?: string
  ) => Promise<VerificationResult>,
  cNonceToEmploy?: string;
  cNonceExp?: number;
  accessTokenExp?: number;
}

export type CreateIdTokenRequestOptionalParams = {
  responseMode?: AuthzResponseMode;
  additionalPayload?: Record<string, any>;
  state?: string;
  nonce?: string;
  expirationTime?: number;
  scope?: string
};

export interface ValidatedClientMetadata {
  responseTypesSupported: string[]
  idTokenAlg: JWA_ALGS[];
  vpFormats: VpFormatsSupported;
};
