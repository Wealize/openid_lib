import { W3CVerifiableCredentialFormats } from "common/formats";
import {
  W3CCredentialStatus,
  W3CSingleCredentialSubject,
  W3CVcSchemaDefinition,
  W3CVerifiableCredential
} from "common/interfaces/w3c_verifiable_credential.interface";
import { CompactVc, VerificationResult } from "common/types";
import { JWK } from "jose";
import { JwtHeader, JwtPayload } from "jsonwebtoken";

export type AccessTokenVerifyCallback = (
  header: JwtHeader,
  payload: JwtPayload
) => Promise<VerificationResult>;

export type VcSignCallback = (
  format: W3CVerifiableCredentialFormats,
  vc: W3CVerifiableCredential | JwtPayload
) => Promise<W3CVerifiableCredential | CompactVc>;

export type DeferredExchangeCallback = (
  acceptanceToken: string
) => Promise<ExtendedCredentialDataOrDeferred | { error: string }>

export interface ExtendedCredentialDataOrDeferred extends CredentialDataOrDeferred {
  types: string[],
  format: W3CVerifiableCredentialFormats,
  subject: string,
}

export type ChallengeNonceRetrieval = (clientId: string) => Promise<string>;

export type GetCredentialSchema = (types: string[]) => Promise<W3CVcSchemaDefinition[]>;

export type GetCredentialData = (
  types: string[],
  holder: string
) => Promise<CredentialDataOrDeferred>;

export interface CredentialDataOrDeferred {
  data?: W3CSingleCredentialSubject,
  deferredCode?: string,
}

export interface GenerateCredentialReponseOptionalParams extends BaseOptionalParams {
  tokenVerification?: {
    publicKeyJwkAuthServer: JWK,
    tokenVerifyCallback: AccessTokenVerifyCallback
  },
}

export interface BaseOptionalParams {
  getValidUntil?: (types: string[]) => Promise<string>;
  getCredentialStatus?: (
    types: string[],
    credentialId: string,
    holder: string
  ) => Promise<W3CCredentialStatus>;
  cNonceToEmploy?: string;
  cNonceExp?: number;
}
