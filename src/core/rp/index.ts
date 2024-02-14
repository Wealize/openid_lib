import { JWK, importJWK, jwtVerify } from "jose";
import { v4 as uuidv4 } from 'uuid';
import { AuthServerMetadata } from "common/interfaces/auth_server_metadata.interface";
import { AuthzRequest, AuthzRequestWithJWT } from "common/interfaces/authz_request.interface";
import { decodeToken, verifyJwtWithExpAndAudience } from "common/utils/jwt.utils";
import { HolderMetadata, ServiceMetadata } from "common/interfaces/client_metadata.interface";
import { AuthorizationDetails } from "common/interfaces/authz_details.interface";
import { ACCESS_TOKEN_EXPIRATION_TIME, C_NONCE_EXPIRATION_TIME, DEFAULT_SCOPE, ID_TOKEN_REQUEST_DEFAULT_EXPIRATION_TIME, JWA_ALGS } from "common/constants";
import { VpFormatsSupported } from "common/types";
import { JwtHeader, JwtPayload } from "jsonwebtoken";
import { AuthzResponseMode } from "common/formats";
import { IdTokenRequest, IdTokenRequestParams } from "common/classes/id_token_request";
import { IdTokenResponse } from "common/interfaces/id_token_response";
import { DIDDocument, DIDResolver, Resolvable, Resolver } from "did-resolver";
import { AuthorizationResponse } from "common/classes/authz_response";
import { TokenRequest } from "common/interfaces/token_request.interface";
import { TokenResponse } from "common/interfaces/token_response.interface";
import { getAuthentificationJWKKeys } from "common/utils/did_document";

// TODO: MOVE TO ANOTHER FILE TO BE USED BY MULTIPLES CLASSES
export type VerificationResult = { valid: boolean, error?: string };

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
};

export interface GenerateAccessTokenOptionalParameters {
  authorizeCodeCallback?: (clientId: string, code: string) => Promise<VerificationResult>;
  preAuthorizeCodeCallback?: (clientId: string, preCode: string, pin?: string) => Promise<VerificationResult>;
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

interface VerifiedBaseAuthzRequest {
  validatedClientMetadata: ValidatedClientMetadata;
  authzRequest: AuthzRequest
}

interface VerifiedIdTokenResponse {
  didDocument: DIDDocument;
  token: string
}

export interface ValidatedClientMetadata {
  responseTypesSupported: string[]
  idTokenAlg: JWA_ALGS[];
  vpFormats: VpFormatsSupported;
};

// TODO: Maybe we need a build to support multiples resolver, or move that responsability to the user
export class OpenIDReliyingParty {
  constructor(
    private defaultMetadataCallback: GetClientDefaultMetada,
    private metadata: AuthServerMetadata,
    private didResolver: Resolver
  ) {

  }

  addDidMethod(methodName: string, resolver: Resolvable) {
    const tmp = {} as Record<string, Resolvable>;
    tmp[methodName] = resolver;
    this.didResolver = new Resolver({
      ...this.didResolver,
      ...tmp
    });
  }

  async createIdTokenRequest(
    clientAuthorizationEndpoint: string,
    audience: string,
    redirectUri: string,
    jwtSignCallback: TokenSignCallback,
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
      params = payload as AuthzRequest;
      if (!params.client_metadata || "jwks_uri" in params.client_metadata === false) {
        // TODO: Define error type
        throw new Error("Expected client metadata with jwks_uri");
      }
      const keys = await fetchJWKs(params.client_metadata.jwks_uri);
      if (!header.kid) {
        throw new Error("No kid specify in JWT header");
      }
      const jwk = selectJwkFromSet(keys, header.kid);
      await verifyJwtWithExpAndAudience(request.request, jwk, this.metadata.issuer);
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

  async verifyIdTokenResponse(
    idTokenResponse: IdTokenResponse,
    verifyCallback: IdTokenVerifyCallback
  ): Promise<VerifiedIdTokenResponse> {
    // Usamos jwebtoken para obtener header y payload
    const { header, payload } = decodeToken(idTokenResponse.id_token);
    const jwtPayload = payload as JwtPayload;
    if (!jwtPayload.iss) {
      // TODO: Define error type
      throw new Error("Id Token must contain iss atribute");
    }
    if (!header.kid) {
      throw new Error("No kid paramater found in ID Token");
    }
    if (this.metadata.id_token_signing_alg_values_supported
      && !this.metadata.id_token_signing_alg_values_supported.includes(header.alg as JWA_ALGS)) {
      throw new Error("Unssuported signing alg for ID Token");
    }
    const didResolution = await this.didResolver.resolve(jwtPayload.iss);
    if (didResolution.didResolutionMetadata.error) {
      throw new Error(`Did resolution failed. Error ${didResolution.didResolutionMetadata.error
        }: ${didResolution.didResolutionMetadata.message}`);
    }
    const didDocument = didResolution.didDocument!;
    const publicKeyJwk = getAuthentificationJWKKeys(didDocument, header.kid);
    await verifyJwtWithExpAndAudience(idTokenResponse.id_token, publicKeyJwk, this.metadata.issuer);
    const verificationResult = await verifyCallback(header, jwtPayload, didDocument);
    if (!verificationResult.valid) {
      throw new Error(`ID Token verification failed ${verificationResult.error}`);
    }
    return {
      token: idTokenResponse.id_token,
      didDocument
    }
  }

  verifyVpTokenResponse() {
    // TODO: PENDING
  }

  createAuthzResponse(
    redirect_uri: string,
    code: string,
    state?: string
  ) {
    // TODO: Maybe this method should be erased. For now, the user defined the code format and content.
    return new AuthorizationResponse(redirect_uri, code, state);
  }

  async generateAccessToken(
    tokenRequest: TokenRequest,
    codeVerifierCallback: (clientId: string, codeVerifier?: string) => Promise<VerificationResult>,
    generateIdToken: boolean,
    tokenSignCallback: TokenSignCallback,
    audience: string,
    optionalParamaters?: GenerateAccessTokenOptionalParameters
  ) {
    if (this.metadata.grant_types_supported
      && !this.metadata.grant_types_supported.includes(tokenRequest.grant_type)) {
      throw new Error("Unssuported grant type");
    }
    switch (tokenRequest.grant_type) {
      case "authorization_code":
        if (!tokenRequest.code) {
          throw new Error(`Grant type "${tokenRequest.grant_type}" invalid parameters`);
        }
        if (!optionalParamaters || !optionalParamaters.authorizeCodeCallback) {
          throw new Error(`No verification callback was provided for "${tokenRequest.grant_type}" grant type`);
        }
        const verificationResult = await optionalParamaters.authorizeCodeCallback(
          tokenRequest.client_id, tokenRequest.code!
        );
        if (!verificationResult.valid) {
          throw new Error(`Invalid "${tokenRequest.grant_type}" provided${verificationResult.error ?
            ": " + verificationResult.error : '.'}`
          );
        }
        break;
      case "pre-authorised_code":
        if (!tokenRequest["pre-authorised_code"]) {
          throw new Error(`Grant type "${tokenRequest.grant_type}" invalid parameters`);
        }
        if (!optionalParamaters || !optionalParamaters.preAuthorizeCodeCallback) {
          throw new Error(`No verification callback was provided for "${tokenRequest.grant_type}" grant type`);
        }
        const verificationResultPre = await optionalParamaters.preAuthorizeCodeCallback(
          tokenRequest.client_id, tokenRequest["pre-authorised_code"]!, tokenRequest.user_pin
        );
        if (!verificationResultPre.valid) {
          throw new Error(`Invalid "${tokenRequest.grant_type}" provided${verificationResultPre.error ?
            ": " + verificationResultPre.error : '.'}`
          );
        }
        break;
      case "vp_token":
        // TODO: PENDING OF VP VERIFICATION METHOD
        if (!tokenRequest.vp_token) {
          throw new Error(`Grant type "vp_token" requires the "vp_token" parameter`);
        }
        throw new Error("Uninplemented");
        break;
    }
    const verificationResult = await codeVerifierCallback(tokenRequest.client_id, tokenRequest.code_verifier);
    if (!verificationResult.valid) {
      throw new Error(`Invalid code_verifier provided${verificationResult.error ?
        ": " + verificationResult.error : '.'}`
      );
    }
    const cNonce = (optionalParamaters &&
      optionalParamaters.cNonceToEmploy) ? optionalParamaters.cNonceToEmploy : uuidv4();
    const nonceExp = (optionalParamaters &&
      optionalParamaters.cNonceExp) ? optionalParamaters.cNonceExp : C_NONCE_EXPIRATION_TIME;
    const tokenExp = (optionalParamaters &&
      optionalParamaters.accessTokenExp) ? optionalParamaters.accessTokenExp : ACCESS_TOKEN_EXPIRATION_TIME;
    const now = Date.now();
    const token = await tokenSignCallback({
      aud: audience,
      iss: this.metadata.issuer,
      sub: tokenRequest.client_id,
      exp: now + tokenExp * 1000,
      nonce: cNonce,
    });
    const result: TokenResponse = {
      access_token: token,
      token_type: "bearer",
      expires_in: tokenExp,
      c_nonce: cNonce,
      c_nonce_expires_in: nonceExp
    };
    if (generateIdToken) {
      result.id_token = await tokenSignCallback({
        iss: this.metadata.issuer,
        sub: tokenRequest.client_id,
        exp: now + tokenExp * 1000,
      },
        this.metadata.id_token_signing_alg_values_supported
      );
    }
    return result;
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
