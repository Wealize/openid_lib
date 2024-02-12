import { OPENID_CREDENTIAL_AUTHZ_DETAILS_TYPE } from "common/constants";
import { W3CVerifiableCredentialFormats } from "common/formats";
import { AuthorizationDetails } from "common/interfaces/authz_details.interface";

export class AuthzDetailsBuilder {
  private types: string[] = [];
  private locations: string[] = [];
  private actions: string[] = [];
  private datatypes: string[] = [];
  private identifier?: string;
  private privileges: string[] = [];

  private constructor(
    private type: string,
    private format: W3CVerifiableCredentialFormats,
  ) { }

  static openIdCredentialBuilder(format: W3CVerifiableCredentialFormats): AuthzDetailsBuilder {
    return new AuthzDetailsBuilder(
      OPENID_CREDENTIAL_AUTHZ_DETAILS_TYPE,
      format
    );
  }

  withTypes(types: string[]): AuthzDetailsBuilder {
    this.types = types;
    return this;
  }

  withLocations(locations: string[]): AuthzDetailsBuilder {
    this.locations = locations;
    return this;
  }

  withActions(actions: string[]): AuthzDetailsBuilder {
    this.actions = actions;
    return this;
  }

  withDatatypes(datatypes: string[]): AuthzDetailsBuilder {
    this.datatypes = datatypes;
    return this;
  }

  withIdentifier(identifier: string): AuthzDetailsBuilder {
    this.identifier = identifier;
    return this;
  }

  withPrivileges(privileges: string[]): AuthzDetailsBuilder {
    this.privileges = privileges;
    return this;
  }

  build(): AuthorizationDetails {
    return {
      type: this.type,
      format: this.format,
      types: this.types,
      locations: this.locations,
      actions: this.actions,
      datatypes: this.datatypes,
      identifier: this.identifier,
      privileges: this.privileges
    }
  }
}
