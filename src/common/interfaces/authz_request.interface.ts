import { AuthzResponseType } from "common/types";
import { AuthorizationDetails } from "./authz_details.interface";
import { HolderMetadata, ServiceMetadata } from "./client_metadata.interface";

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
