import { JWK, importJWK, jwtVerify } from "jose";
import { v4 as uuidv4 } from 'uuid';
import { AuthServerMetadata } from "common/interfaces/auth_server_metadata.interface";
import { AuthzRequest, AuthzRequestWithJWT } from "common/interfaces/authz_request.interface";
import { decodeToken } from "common/utils/jwt.utils";
import { HolderMetadata, ServiceMetadata } from "common/interfaces/client_metadata.interface";
import { AuthorizationDetails } from "common/interfaces/authz_details.interface";
import { DEFAULT_SCOPE, ID_TOKEN_REQUEST_DEFAULT_EXPIRATION_TIME, JWA_ALGS } from "common/constants";
import { VpFormatsSupported } from "common/types";
import { JwtPayload } from "jsonwebtoken";
import { AuthzResponseMode } from "common/formats";
import { IdTokenRequest, IdTokenRequestParams } from "common/classes/id_token_request";

// TODO: MOVE TO ANOTHER FILE TO BE USED BY MULTIPLES CLASSES
export type VerificationResult = { valid: boolean, error?: string };

export type IdTokenSignCallback = (
  payload: JwtPayload,
  supportedSignAlg?: JWA_ALGS[]
) => Promise<string>;

export type GetClientDefaultMetada = () => Promise<HolderMetadata>;

export type VerifyBaseAuthzRequestOptionalParams = {
  authzDetailsVerifyCallback?: (authDetails: AuthorizationDetails) => Promise<VerificationResult>;
  scopeVerifyCallback?: (scope: string) => Promise<VerificationResult>;
};

export type CreateIdTokenRequestOptionalParams = {
  responseMode?: AuthzResponseMode;
  additionalPayload?: Record<string, any>;
  state?: string;
  nonce?: string;
  expirationTime?: number;
  scope?: string
};

interface VerifiedBaseAuthzRequest {
  validatedClientMetadata: ValidatedClientMetadata;
  authzRequest: AuthzRequest
}

export interface ValidatedClientMetadata {
  responseTypesSupported: string[]
  idTokenAlg: JWA_ALGS[];
  vpFormats: VpFormatsSupported;
};

export class OpenIDReliyingParty {
  constructor(
    private defaultMetadataCallback: GetClientDefaultMetada,
    private metadata: AuthServerMetadata
  ) {

  }

  async createIdTokenRequest(
    clientAuthorizationEndpoint: string,
    audience: string,
    redirectUri: string,
    jwtSignCallback: IdTokenSignCallback,
    additionalParameters?: CreateIdTokenRequestOptionalParams
  ): Promise<IdTokenRequest> {
    additionalParameters = {
      ...{
        responseMode: "direct_post",
        state: uuidv4(),
        scope: DEFAULT_SCOPE,
        expirationTime: ID_TOKEN_REQUEST_DEFAULT_EXPIRATION_TIME
      },
      ...additionalParameters
    };
    const requestParams: IdTokenRequestParams = {
      response_type: "id_token",
      scope: additionalParameters.scope!,
      redirect_uri: redirectUri,
      response_mode: additionalParameters.responseMode,
      state: additionalParameters.state,
      nonce: additionalParameters.nonce
    };
    const idToken = await jwtSignCallback({
      aud: audience,
      iss: this.metadata.issuer,
      exp: Date.now() + additionalParameters.expirationTime!,
      ...requestParams,
      ...additionalParameters.additionalPayload
    },
      this.metadata.id_token_signing_alg_values_supported
    );
    return new IdTokenRequest(requestParams, idToken, clientAuthorizationEndpoint);
  }

  createIdTokenRequestFromBaseAuthzRequest() {

  }

  createVpTokenRequest() {
    // TODO: PENDING
  }

  async verifyBaseAuthzRequest(
    request: AuthzRequestWithJWT,
    additionalParameters?: VerifyBaseAuthzRequestOptionalParams
  ): Promise<VerifiedBaseAuthzRequest> {
    // TODO: RESPONSE MODE SHOULD BE CHECKED
    let params: AuthzRequest;
    if (!request.request) {
      params = request;
    } else {
      // TODO: ADD REQUEST_URI PARAMETER
      if (this.metadata.request_parameter_supported === false) {
        throw new Error("Unssuported request parameter");
      }
      const { header, payload } = decodeToken(request.request);
      if (this.metadata.request_object_signing_alg_values_supported &&
        !this.metadata.request_object_signing_alg_values_supported.includes(header.alg as JWA_ALGS)) {
        throw new Error("Unssuported request signing alg");
      }
      const payloadJWT = payload as JwtPayload;
      if (!payloadJWT.exp || payloadJWT.exp < Date.now()) {
        throw new Error("JWT is expired or does not have exp parameter");
      }
      if (!payloadJWT.aud || payloadJWT.aud !== this.metadata.issuer) {
        throw new Error("JWT audience is invalid or is not defined");
      }
      params = payloadJWT as AuthzRequest;
      if (!params.client_metadata || "jwks_uri" in params.client_metadata === false) {
        // TODO: Define error type
        throw new Error("Expected client metadata with jwks_uri");
      }
      const keys = await fetchJWKs(params.client_metadata.jwks_uri);
      if (!header.kid) {
        throw new Error("No kid specify in JWT header");
      }
      const jwk = selectJwkFromSet(keys, header.kid);
      const publicKey = await importJWK(jwk);
      await jwtVerify(request.request, publicKey);
    }
    params.client_metadata = await this.resolveClientMetadata(params.client_metadata);
    const validatedClientMetadata = this.validateClientMetadata(params.client_metadata);
    if (additionalParameters) {
      if (additionalParameters.scopeVerifyCallback) {
        const scopeVerificationResult = await additionalParameters.scopeVerifyCallback(params.scope);
        if (!scopeVerificationResult.valid) {
          throw new Error(
            `Invalid scope specified` +
            `${scopeVerificationResult.error ? ": " + scopeVerificationResult.error : '.'}`
          );
        }
      }
      if (params.authorization_details) {
        for (const details of params.authorization_details) {
          if (details.locations && !details.locations.includes(this.metadata.issuer)) {
            throw new Error("Location must contains Issuer client id value");
          }
          if (additionalParameters.authzDetailsVerifyCallback) {
            const authDetailsVerificationResult = await additionalParameters.authzDetailsVerifyCallback(details);
            if (!authDetailsVerificationResult.valid) {
              throw new Error(
                `Invalid authorization details specified` +
                `${authDetailsVerificationResult.error ? ": " + authDetailsVerificationResult.error : '.'}`
              );
            }
          }
        }
      }
    }
    return {
      validatedClientMetadata,
      authzRequest: params
    }
  }

  verifyIdTokenResponse() {

  }

  verifyVpTokenResponse() {
    // TODO: PENDING
  }

  createAuthzResponse() {

  }

  private validateClientMetadata(clientMetadata: HolderMetadata): ValidatedClientMetadata {
    const responseTypesSupported = [];
    const idTokenAlg: JWA_ALGS[] = [];
    const vpFormats: VpFormatsSupported = {}
    // Check response_types_supported
    for (const responseType in this.metadata.response_types_supported) {
      if (clientMetadata.response_types_supported!.includes(responseType)) {
        responseTypesSupported.push(responseType);
      }
    }
    if (this.metadata.id_token_signing_alg_values_supported) {
      for (const alg in clientMetadata.id_token_signing_alg_values_supported) {
        if (clientMetadata.id_token_signing_alg_values_supported!.includes(alg as JWA_ALGS)) {
          idTokenAlg.push(alg as JWA_ALGS);
        }
      }
    }
    if (this.metadata.vp_formats_supported) {
      for (const format in clientMetadata!.vp_formats_supported) {
        if (this.metadata.vp_formats_supported![format as keyof VpFormatsSupported]) {
          const intersectArray: JWA_ALGS[] = [];
          for (const alg of clientMetadata!.vp_formats_supported[format as keyof VpFormatsSupported]?.alg_values_supported!) {
            if (this.metadata.vp_formats_supported![format as keyof VpFormatsSupported]?.alg_values_supported.includes(alg)) {
              intersectArray.push(alg);
            }
          }
          vpFormats[format as keyof VpFormatsSupported] = { alg_values_supported: intersectArray };
        }
      }
    }
    return {
      responseTypesSupported,
      idTokenAlg,
      vpFormats
    }
  }

  private async resolveClientMetadata(
    metadata?: Record<string, any>
  ): Promise<HolderMetadata | ServiceMetadata> {
    const defaultMetadata = await this.defaultMetadataCallback();
    return metadata ? { ...await this.defaultMetadataCallback(), ...metadata } : defaultMetadata;
  }
}

async function fetchJWKs(url: string): Promise<JWK[]> {
  try {
    const response = await fetch(url);
    const jwks = await response.json();
    if (jwks.keys) {
      // TODO: Define error type
      throw new Error("No 'keys' paramater found");
    }
    return jwks['keys'];
  } catch (e: any) {
    // TODO: Define error type
    throw new Error(`Can't recover credential issuer JWKs: ${e}`);
  }
}

function selectJwkFromSet(jwks: JWK[], kid: string): JWK {
  const jwk = jwks.find((jwk) => jwk.kid === kid);
  if (!jwk) {
    // TODO: Define error type
    throw new Error(`No JWK found with kid ${kid}`);
  }
  return jwk;
}
