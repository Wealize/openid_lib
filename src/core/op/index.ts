import { v4 as uuidv4 } from 'uuid';
import querystring from "querystring";
import { AuthzRequestBuilder } from "common/builders/authz/authz_request.builder";
import { AuthorizationDetails } from "common/interfaces/authz_details.interface";
import { AuthzRequest, AuthzRequestLocation } from "common/interfaces/authz_request.interface";
import { HolderMetadata, ServiceMetadata } from "common/interfaces/client_metadata.interface";
import { AuthzResponseType } from "common/types";
import { generateChallenge } from "common/utils/pkce.utils";

interface AuthzRequestMethodData {
  jwt?: string,
  url: string,
  state: string,
}

export class OpenIDProvider {
  constructor(
    private redirectUri: string,
    // For now, support for JWT. TODO: EXPAND SUPPORT TO JLD
    private requestCallback: AuthzSignCallback,
    private metadata: ServiceMetadata | HolderMetadata,
    private clientId: string,
  ) {

  }

  // TODO: DERIVE FROM CREDENTIAL OFFER FOR ISSUER STATE AND EVEN AUTHZ DETAILS
  async createBaseAuthzRequest(
    url: string,
    requestLocation: AuthzRequestLocation,
    response_type: AuthzResponseType, // Most probably could be set to "code"
    authzDetails: AuthorizationDetails,
    scope: string,
    pkceChallenge?: {
      code_challenge: string,
      code_challenge_method: string
    }
  ): Promise<AuthzRequestMethodData> {
    let code_challenge, code_challenge_method;
    if (pkceChallenge) {
      code_challenge = pkceChallenge.code_challenge;
      code_challenge_method = pkceChallenge.code_challenge_method;
    } else {
      code_challenge = await generateChallenge();
      code_challenge_method = "S256"; // TODO: Define new type
    }
    const hasParams = url.includes("?");
    const state = uuidv4();
    const authzBaseRequest = new AuthzRequestBuilder(
      response_type,
      this.clientId,
      this.redirectUri
    )
      .withScope(scope)
      .withMetadata(this.metadata)
      .addAuthzDetails(authzDetails)
      .withCodeChallenge(code_challenge, code_challenge_method)
      .withState(state)
      .build();
    let location;
    let result: AuthzRequestMethodData;
    switch (requestLocation) {
      case AuthzRequestLocation.JWT_OBJECT:
        const request = await this.requestCallback(authzBaseRequest);
        location = `${url}${hasParams ? "&" : "/?"}${querystring.stringify(
          { ...authzBaseRequest, request } as Record<any, any>)}`;
        result = { url: location, state, jwt: request };
        break;
      case AuthzRequestLocation.PLAIN_REQUEST:
        location = `${url}${hasParams ? "&" : "/?"}${querystring.stringify(authzBaseRequest as Record<any, any>)}`;
        result = { url: location, state };
        break;
    }
    return result;
  }

  createIdTokenReponse() {

  }

  createVpTokenResponse() {

  }

  verifyIdTokenRequest() {

  }

  verifyVpTokenResponse() {

  }

  verifyAuthzResponse() {

  }

}

export type AuthzSignCallback = (data: AuthzRequest) => Promise<string>;
