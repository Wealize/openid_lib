import {
  CredentialOffer,
  CredentialOfferGrants,
  CredentialsOfferData
} from 'common/interfaces/credential_offer.interface';
import { v4 as uuidv4 } from 'uuid';

export class CredentialOfferBuilder {
  private credentials: CredentialsOfferData[] = [];
  private grants?: CredentialOfferGrants;

  constructor(
    private credential_issuer: string
  ) { }

  static authorizeCredentialOffer(
    credential_issuer: string,
    issuer_state?: string
  ): CredentialOfferBuilder {
    return new CredentialOfferBuilder(credential_issuer).withAuthGrant(issuer_state);
  }

  static preAuthorizeCredentialOffer(
    credential_issuer: string,
    pinRequired: boolean,
    preCode?: string
  ): CredentialOfferBuilder {
    return new CredentialOfferBuilder(credential_issuer).withPreAuthGrant(pinRequired, preCode);
  }

  addCredential(credentialData: CredentialsOfferData): CredentialOfferBuilder {
    this.credentials.push(credentialData);
    return this;
  }

  withAuthGrant(issuer_state?: string): CredentialOfferBuilder {
    if (!issuer_state) {
      issuer_state = uuidv4();
    }
    if (!this.grants) {
      this.grants = { authorization_code: { issuer_state } };
    } else {
      this.grants.authorization_code = { issuer_state };
    }
    return this;
  }

  withPreAuthGrant(pinRequired: boolean, preCode?: string): CredentialOfferBuilder {
    if (!preCode) {
      preCode = uuidv4();
    }
    if (!this.grants) {
      this.grants = {
        "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
          "pre-authorized_code": preCode,
          user_pin_required: pinRequired
        }
      };
    } else {
      this.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"] = {
        "pre-authorized_code": preCode,
        user_pin_required: pinRequired
      };
    }
    return this;
  }

  build(): CredentialOffer {
    return {
      credential_issuer: this.credential_issuer,
      credentials: this.credentials,
      grants: this.grants
    }
  }
}
