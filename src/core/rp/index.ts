import { JWK } from "jose";
import { v4 as uuidv4 } from 'uuid';
import {
  AuthServerMetadata
} from "../../common/interfaces/auth_server_metadata.interface.js";
import {
  AuthzRequest,
  AuthzRequestWithJWT
} from "../../common/interfaces/authz_request.interface.js";
import {
  decodeToken,
  verifyJwtWithExpAndAudience
} from "../../common/utils/jwt.utils.js";
import {
  HolderMetadata,
  ServiceMetadata
} from "../../common/interfaces/client_metadata.interface.js";
import {
  ACCESS_TOKEN_EXPIRATION_TIME,
  C_NONCE_EXPIRATION_TIME,
  DEFAULT_SCOPE,
  ID_TOKEN_REQUEST_DEFAULT_EXPIRATION_TIME,
  JWA_ALGS
} from "../../common/constants/index.js";
import { VerificationResult, VpFormatsSupported } from "../../common/types/index.js";
import { JwtPayload } from "jsonwebtoken";
import {
  IdTokenRequest,
  IdTokenRequestParams
} from "../../common/classes/id_token_request.js";
import { IdTokenResponse } from "../../common/interfaces/id_token_response.js";
import { DIDDocument, Resolvable, Resolver } from "did-resolver";
import { AuthorizationResponse } from "../../common/classes/authz_response.js";
import { TokenRequest } from "../../common/interfaces/token_request.interface.js";
import { TokenResponse } from "../../common/interfaces/token_response.interface.js";
import { getAuthentificationJWKKeys } from "../../common/utils/did_document.js";
import * as RpTypes from "./types.js";
import {
  AccessDenied,
  InsufficienteParamaters,
  InternalError,
  InvalidGrant,
  InvalidRequest,
  InvalidScope,
  UnauthorizedClient,
  UnsupportedGrantType
} from "../../common/classes/index.js";

export interface VerifiedBaseAuthzRequest {
  validatedClientMetadata: RpTypes.ValidatedClientMetadata;
  authzRequest: AuthzRequest
}

interface VerifiedIdTokenResponse {
  didDocument: DIDDocument;
  token: string
}

// TODO: Maybe we need a build to support multiples resolver, or move that responsability to the user
export class OpenIDReliyingParty {
  constructor(
    private defaultMetadataCallback: RpTypes.GetClientDefaultMetada,
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
    jwtSignCallback: RpTypes.TokenSignCallback,
    additionalParameters?: RpTypes.CreateIdTokenRequestOptionalParams
  ): Promise<IdTokenRequest> {
    additionalParameters = {
      ...{
        responseMode: "direct_post",
        nonce: uuidv4(),
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
    additionalParameters?: RpTypes.VerifyBaseAuthzRequestOptionalParams
  ): Promise<VerifiedBaseAuthzRequest> {
    // TODO: RESPONSE MODE SHOULD BE CHECKED
    let params: AuthzRequest;
    if (!request.request) {
      params = request;
    } else {
      // TODO: ADD REQUEST_URI PARAMETER
      if (this.metadata.request_parameter_supported === false) {
        throw new InvalidRequest("Unsuported request parameter");
      }
      const { header, payload } = decodeToken(request.request);
      if (this.metadata.request_object_signing_alg_values_supported &&
        !this.metadata.request_object_signing_alg_values_supported.includes(header.alg as JWA_ALGS)) {
        throw new InvalidRequest("Unsuported request signing alg");
      }
      params = payload as AuthzRequest;
      if (!params.client_metadata || "jwks_uri" in params.client_metadata === false) {
        throw new InvalidRequest("Expected client metadata with jwks_uri");
      }
      const keys = await fetchJWKs(params.client_metadata.jwks_uri);
      if (!header.kid) {
        throw new InvalidRequest("No kid specify in JWT header");
      }
      const jwk = selectJwkFromSet(keys, header.kid);
      try {
        await verifyJwtWithExpAndAudience(request.request, jwk, this.metadata.issuer);
      } catch (error: any) {
        throw new InvalidRequest(error.message);
      }
    }
    params.client_metadata = await this.resolveClientMetadata(params.client_metadata);
    const validatedClientMetadata = this.validateClientMetadata(params.client_metadata);
    if (additionalParameters) {
      if (additionalParameters.scopeVerifyCallback) {
        const scopeVerificationResult = await additionalParameters.scopeVerifyCallback(params.scope);
        if (!scopeVerificationResult.valid) {
          throw new InvalidScope(
            `Invalid scope specified` +
            `${scopeVerificationResult.error ? ": " + scopeVerificationResult.error : '.'}`
          );
        }
      }
      if (params.authorization_details) {
        for (const details of params.authorization_details) {
          if (details.locations && !details.locations.includes(this.metadata.issuer)) {
            throw new InvalidRequest("Location must contains Issuer client id value");
          }
          if (additionalParameters.authzDetailsVerifyCallback) {
            const authDetailsVerificationResult = await additionalParameters.authzDetailsVerifyCallback(details);
            if (!authDetailsVerificationResult.valid) {
              throw new InvalidRequest(
                `Invalid authorization details specified` +
                `${authDetailsVerificationResult.error ? ": " + authDetailsVerificationResult.error : '.'}`
              );
            }
          }
        }
      }
      if (additionalParameters.issuerStateVerifyCallback) {
        if (!params.issuer_state) {
          throw new InvalidRequest(`An "issuer_state" parameter is required`);
        }
        const issuerStateVerificationResult =
          await additionalParameters.issuerStateVerifyCallback(params.issuer_state);
        if (!issuerStateVerificationResult.valid) {
          throw new InvalidRequest(
            `Invalid "issuer_state" provided` +
            `${issuerStateVerificationResult.error ? ": " + issuerStateVerificationResult.error : '.'}`
          );
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
    verifyCallback: RpTypes.IdTokenVerifyCallback
  ): Promise<VerifiedIdTokenResponse> {
    // Usamos jwebtoken para obtener header y payload
    const { header, payload } = decodeToken(idTokenResponse.id_token);
    const jwtPayload = payload as JwtPayload;
    if (!jwtPayload.iss) {
      throw new InvalidRequest("Id Token must contain iss atribute");
    }
    if (!header.kid) {
      throw new InvalidRequest("No kid paramater found in ID Token");
    }
    if (this.metadata.id_token_signing_alg_values_supported
      && !this.metadata.id_token_signing_alg_values_supported.includes(header.alg as JWA_ALGS)) {
      throw new InvalidRequest("Unsuported signing alg for ID Token");
    }
    const didResolution = await this.didResolver.resolve(jwtPayload.iss);
    if (didResolution.didResolutionMetadata.error) {
      throw new UnauthorizedClient(
        `Did resolution failed. Error ${didResolution.didResolutionMetadata.error
        }: ${didResolution.didResolutionMetadata.message}`
      );
    }
    const didDocument = didResolution.didDocument!;
    const publicKeyJwk = getAuthentificationJWKKeys(didDocument, header.kid);
    try {
      await verifyJwtWithExpAndAudience(
        idTokenResponse.id_token,
        publicKeyJwk,
        this.metadata.issuer
      );
    } catch (error: any) {
      throw new AccessDenied(error.message);
    }
    const verificationResult = await verifyCallback(header, jwtPayload, didDocument);
    if (!verificationResult.valid) {
      throw new InvalidRequest(`ID Token verification failed ${verificationResult.error}`);
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
    generateIdToken: boolean,
    tokenSignCallback: RpTypes.TokenSignCallback,
    audience: string,
    optionalParamaters?: RpTypes.GenerateAccessTokenOptionalParameters
  ) {
    if (this.metadata.grant_types_supported
      && !this.metadata.grant_types_supported.includes(tokenRequest.grant_type)) {
      throw new UnsupportedGrantType(
        `Grant type "${tokenRequest.grant_type}" not supported`
      );
    }
    switch (tokenRequest.grant_type) {
      case "authorization_code":
        if (!tokenRequest.code) {
          throw new InvalidGrant(
            `Grant type "${tokenRequest.grant_type}" invalid parameters`
          );
        }
        if (!optionalParamaters || !optionalParamaters.authorizeCodeCallback) {
          throw new InsufficienteParamaters(
            `No verification callback was provided for "${tokenRequest.grant_type}" grant type`
          );
        }
        let verificationResult = await optionalParamaters.authorizeCodeCallback(
          tokenRequest.client_id, tokenRequest.code!
        );
        if (!verificationResult.valid) {
          throw new InvalidGrant(
            `Invalid "${tokenRequest.grant_type}" provided${verificationResult.error ?
              ": " + verificationResult.error : '.'}`
          );
        }
        if (!optionalParamaters.codeVerifierCallback) {
          throw new InsufficienteParamaters(
            `No "code_verifier" verification callback was provided.`
          );
        }
        verificationResult = await optionalParamaters.codeVerifierCallback(
          tokenRequest.client_id,
          tokenRequest.code_verifier
        );
        if (!verificationResult.valid) {
          throw new InvalidGrant(`Invalid code_verifier provided${verificationResult.error ?
            ": " + verificationResult.error : '.'}`
          );
        }
        break;
      case "pre-authorised_code":
        if (!tokenRequest["pre-authorised_code"]) {
          throw new InvalidGrant(`Grant type "${tokenRequest.grant_type}" invalid parameters`);
        }
        if (!optionalParamaters || !optionalParamaters.preAuthorizeCodeCallback) {
          throw new InsufficienteParamaters(
            `No verification callback was provided for "${tokenRequest.grant_type}" grant type`
          );
        }
        const verificationResultPre = await optionalParamaters.preAuthorizeCodeCallback(
          tokenRequest.client_id, tokenRequest["pre-authorised_code"]!, tokenRequest.user_pin
        );
        if (!verificationResultPre.valid) {
          throw new InvalidGrant(
            `Invalid "${tokenRequest.grant_type}" provided${verificationResultPre.error ?
              ": " + verificationResultPre.error : '.'}`
          );
        }
        break;
      case "vp_token":
        // TODO: PENDING OF VP VERIFICATION METHOD
        if (!tokenRequest.vp_token) {
          throw new InsufficienteParamaters(`Grant type "vp_token" requires the "vp_token" parameter`);
        }
        throw new InternalError("Uninplemented");
        break;
    }
    const cNonce = (optionalParamaters &&
      optionalParamaters.cNonceToEmploy) ?
      optionalParamaters.cNonceToEmploy : uuidv4();
    const tokenExp = (optionalParamaters &&
      optionalParamaters.accessTokenExp) ?
      optionalParamaters.accessTokenExp : ACCESS_TOKEN_EXPIRATION_TIME;
    const now = Math.floor(Date.now() / 1000);
    const token = await tokenSignCallback({
      aud: audience,
      iss: this.metadata.issuer,
      sub: tokenRequest.client_id,
      exp: now + tokenExp,
      nonce: cNonce,
    });
    const result: TokenResponse = {
      access_token: token,
      token_type: "bearer",
      expires_in: tokenExp,
      c_nonce: cNonce,
      c_nonce_expires_in: (optionalParamaters &&
        optionalParamaters.cNonceExp) ? optionalParamaters.cNonceExp : C_NONCE_EXPIRATION_TIME
    };
    if (generateIdToken) {
      result.id_token = await tokenSignCallback({
        iss: this.metadata.issuer,
        sub: tokenRequest.client_id,
        exp: now + tokenExp,
      },
        this.metadata.id_token_signing_alg_values_supported
      );
    }
    return result;
  }

  private validateClientMetadata(clientMetadata: HolderMetadata): RpTypes.ValidatedClientMetadata {
    const idTokenAlg: JWA_ALGS[] = [];
    const vpFormats: VpFormatsSupported = {}
    if (this.metadata.id_token_signing_alg_values_supported &&
      clientMetadata.id_token_signing_alg_values_supported) {
      for (const alg of clientMetadata.id_token_signing_alg_values_supported) {
        if (this.metadata.id_token_signing_alg_values_supported.includes(alg as JWA_ALGS)) {
          idTokenAlg.push(alg as JWA_ALGS);
        }
      }
    }
    if (this.metadata.vp_formats_supported) {
      for (const format in clientMetadata!.vp_formats_supported) {
        if (this.metadata.vp_formats_supported![format as keyof VpFormatsSupported]) {
          const intersectArray: JWA_ALGS[] = [];
          for (const alg of clientMetadata!.vp_formats_supported[
            format as keyof VpFormatsSupported]?.alg_values_supported!) {
            if (this.metadata.vp_formats_supported![
              format as keyof VpFormatsSupported]?.alg_values_supported.includes(alg)) {
              intersectArray.push(alg);
            }
          }
          vpFormats[format as keyof VpFormatsSupported] = { alg_values_supported: intersectArray };
        }
      }
    }
    return {
      responseTypesSupported: clientMetadata.response_types_supported ?? [],
      idTokenAlg,
      vpFormats
    }
  }

  private async resolveClientMetadata(
    metadata?: Record<string, any>
  ): Promise<HolderMetadata | ServiceMetadata> {
    const defaultMetadata = await this.defaultMetadataCallback();
    return metadata ? { ...defaultMetadata, ...metadata } : defaultMetadata;
  }
}

async function fetchJWKs(url: string): Promise<JWK[]> {
  try {
    const response = await fetch(url);
    const jwks = await response.json();
    if (jwks.keys) {
      throw new InvalidRequest("No 'keys' paramater found");
    }
    return jwks['keys'];
  } catch (e: any) {
    throw new InternalError(`Can't recover credential issuer JWKs: ${e}`);
  }
}

function selectJwkFromSet(jwks: JWK[], kid: string): JWK {
  const jwk = jwks.find((jwk) => jwk.kid === kid);
  if (!jwk) {
    throw new InvalidRequest(`No JWK found with kid ${kid}`);
  }
  return jwk;
}

export * from "./types.js";
