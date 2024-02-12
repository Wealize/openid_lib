import { DEFAULT_SCOPE, JWA_ALGS } from "common/constants";
import { AuthorizationDetails } from "common/interfaces/authz_details.interface";
import { AuthzRequest } from "common/interfaces/authz_request.interface";
import { HolderMetadata, ServiceMetadata } from "common/interfaces/client_metadata.interface";
import { AuthzResponseType } from "common/types";

export class AuthzRequestBuilder {
  private scope: string = DEFAULT_SCOPE;
  private issuer_state?: string;
  private state?: string;
  private authorization_details?: AuthorizationDetails[];
  private nonce?: string;
  private code_challenge?: string;
  private code_challenge_method?: string;
  private client_metadata?: HolderMetadata | ServiceMetadata;

  constructor(
    private response_type: AuthzResponseType,
    private client_id: string,
    private redirect_uri: string,
    private imposeOpenIdScope = true
  ) { }

  static holderAuthzRequestBuilder(
    response_type: AuthzResponseType,
    client_id: string,
    redirect_uri: string,
    metadata: HolderMetadata,
    code_challenge: string,
    code_challenge_method: JWA_ALGS,
    issuer_state?: string,
  ) {
    const builder = new AuthzRequestBuilder(
      response_type,
      client_id,
      redirect_uri
    )
      .withMetadata(metadata)
      .withCodeChallenge(code_challenge, code_challenge_method);
    if (issuer_state) {
      builder.withIssuerState(issuer_state);
    }
    return builder;
  }

  static serviceAuthzRequestBuilder(
    response_type: AuthzResponseType,
    client_id: string,
    redirect_uri: string,
    metadata: ServiceMetadata,
    issuer_state?: string,
  ) {
    const builder = new AuthzRequestBuilder(
      response_type,
      client_id,
      redirect_uri
    )
      .withMetadata(metadata);
    if (issuer_state) {
      builder.withIssuerState(issuer_state);
    }
    return builder;
  }

  withMetadata(metadata: HolderMetadata | ServiceMetadata): AuthzRequestBuilder {
    this.client_metadata = metadata;
    return this;
  }

  withCodeChallenge(code_challenge: string, method: string): AuthzRequestBuilder {
    this.code_challenge = code_challenge;
    this.code_challenge_method = method;
    return this;
  }

  withScope(scope: string): AuthzRequestBuilder {
    if (this.imposeOpenIdScope && !scope.includes(DEFAULT_SCOPE)) {
      // TODO: Define error enum
      throw new Error(`Scope must contain ${DEFAULT_SCOPE}`);
    }
    this.scope = scope;
    return this;
  }

  withIssuerState(issuerState: string): AuthzRequestBuilder {
    this.issuer_state = issuerState;
    return this;
  }

  withState(state: string): AuthzRequestBuilder {
    this.state = state;
    return this;
  }

  withNonce(nonce: string): AuthzRequestBuilder {
    this.nonce = nonce;
    return this;
  }

  addAuthzDetails(authorizationDetails: AuthorizationDetails): AuthzRequestBuilder {
    if (!this.authorization_details) {
      this.authorization_details = [];
    }
    this.authorization_details.push(authorizationDetails);
    return this;
  }

  build(): AuthzRequest {
    return {
      response_type: this.response_type,
      client_id: this.client_id,
      redirect_uri: this.redirect_uri,
      scope: this.scope,
      issuer_state: this.issuer_state,
      state: this.state,
      authorization_details: this.authorization_details,
      nonce: this.nonce,
      code_challenge: this.code_challenge,
      code_challenge_method: this.code_challenge_method,
      client_metadata: this.client_metadata
    }
  }
}
