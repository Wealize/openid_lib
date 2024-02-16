import { AuthzResponseType } from "../types/index.js";
import { AuthorizationDetails } from "./authz_details.interface.js";
import { HolderMetadata, ServiceMetadata } from "./client_metadata.interface.js";

export interface AuthzRequest {
  response_type: AuthzResponseType;
  client_id: string;
  redirect_uri: string;
  scope: string;
  issuer_state?: string;
  state?: string;
  authorization_details?: AuthorizationDetails[];
  nonce?: string;
  code_challenge?: string;
  code_challenge_method?: string;
  client_metadata?: HolderMetadata | ServiceMetadata
}

export interface AuthzRequestWithJWT extends AuthzRequest {
  request?: string
};

export enum AuthzRequestLocation {
  PLAIN_REQUEST,
  JWT_OBJECT,
}
