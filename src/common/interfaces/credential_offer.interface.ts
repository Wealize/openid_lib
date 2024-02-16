import { W3CVerifiableCredentialFormats } from "../formats/index.js";

export interface GrantPreAuthorizeCode {
  "pre-authorized_code": string;
  user_pin_required: boolean;
}

export interface GrantAuthorizationCode {
  issuer_state: string;
}

export interface CredentialOfferGrants {
  authorization_code?: GrantAuthorizationCode;
  "urn:ietf:params:oauth:grant-type:pre-authorized_code"?: GrantPreAuthorizeCode;
}

export interface CredentialTrustFramework {
  name: string;
  type: string;
  uri?: string;
}

export interface CredentialsOfferData {
  format: W3CVerifiableCredentialFormats;
  types: string[]; // Only for W3C Verifiable Credentials
  trust_framework?: CredentialTrustFramework;
}

export interface CredentialOffer {
  credential_issuer: string;
  credentials: CredentialsOfferData[];
  grants?: CredentialOfferGrants;
}
