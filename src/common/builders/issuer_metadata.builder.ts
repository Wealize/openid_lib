import { v4 as uuidv4 } from 'uuid';
import { W3CVerifiableCredentialFormats } from "common/formats";
import {
  CredentialSupported,
  IssuerMetadata,
  VerifiableCredentialDisplay
} from 'common/interfaces/issuer_metadata.interface';
import { isHttps } from 'common/utils';
import { InternalError } from 'common/classes';

export class IssuerMetadataBuilder {
  private authorization_server?: string;
  private deferred_credential_endpoint?: string;
  private batch_credential_endpoint?: string;
  private credentials_supported: Map<string, CredentialSupported> = new Map();
  constructor(
    private credential_issuer: string,
    private credential_endpoint: string,
    private imposeHttps = true,
  ) {
    if (imposeHttps) {
      if (!isHttps(credential_issuer)) {
        // TODO: Define error enum
        throw new InternalError("Is not https");
      }
      if (!isHttps(credential_endpoint)) {
        // TODO: Define error enum
        throw new InternalError("Is not https");
      }
    }
  }

  private assertUrlIsHttps(url: string, assertedParameter: string) {
    if (this.imposeHttps) {
      if (!isHttps(url)) {
        // TODO: Define error enum
        throw new InternalError(`${assertedParameter} is not https`);
      }
    }
  }

  withAuthorizationServer(url: string): IssuerMetadataBuilder {
    this.assertUrlIsHttps(url, "authorization_server");
    this.authorization_server = url;
    return this;
  }

  withDeferredCredentialEndpoint(url: string): IssuerMetadataBuilder {
    this.assertUrlIsHttps(url, "deferred_credential_endpoint");
    this.deferred_credential_endpoint = url;
    return this;
  }

  withBatchCredentialEndpoint(url: string): IssuerMetadataBuilder {
    this.assertUrlIsHttps(url, "batch_credential_endpoint");
    this.batch_credential_endpoint = url;
    return this;
  }

  addCredentialSupported(supportedCredential: CredentialSupported): IssuerMetadataBuilder {
    let id: string;
    if (!supportedCredential.id) {
      id = uuidv4();
    } else {
      if (this.credentials_supported.get(supportedCredential.id)) {
        // TODO: Define error enum
        throw new InternalError("Credential supported already defined");
      }
      id = supportedCredential.id;
    }
    this.credentials_supported.set(id, supportedCredential);
    return this;
  }

  build(): IssuerMetadata {
    return {
      credential_issuer: this.credential_issuer,
      authorization_server: this.authorization_server,
      credential_endpoint: this.credential_endpoint,
      deferred_credential_endpoint: this.deferred_credential_endpoint,
      batch_credential_endpoint: this.batch_credential_endpoint,
      credentials_supported: Array.from(this.credentials_supported.values())
    };;
  }
}

export class CredentialSupportedBuilder {
  private format: W3CVerifiableCredentialFormats = "jwt_vc_json";
  private id?: string;
  private types: string[] = [];
  private display?: VerifiableCredentialDisplay[];

  withFormat(format: W3CVerifiableCredentialFormats): CredentialSupportedBuilder {
    this.format = format;
    return this;
  }

  withId(id: string): CredentialSupportedBuilder {
    this.id = id;
    return this;
  }

  withTypes(types: string[]): CredentialSupportedBuilder {
    this.types = types;
    return this;
  }

  addDisplay(display: VerifiableCredentialDisplay): CredentialSupportedBuilder {
    if (!this.display) {
      this.display = [];
    }
    this.display.push(display);
    return this;
  }

  build(): CredentialSupported {
    return {
      format: this.format,
      id: this.id,
      types: this.types,
      display: this.display
    }
  }

}

export class VerifiableCredentialDisplayBuilder {
  constructor(private name: string) { }
  private locale?: string;
  private logo?: JSON;
  private url?: string;
  private alt_text?: string;
  private description?: string;
  private background_color?: string;
  private text_color?: string

  withLocale(locale: string): VerifiableCredentialDisplayBuilder {
    this.locale = locale;
    return this;
  }

  withLogo(logo: JSON): VerifiableCredentialDisplayBuilder {
    this.logo = logo;
    return this;
  }

  withUrl(url: string): VerifiableCredentialDisplayBuilder {
    this.url = url;
    return this;
  }

  withAltText(text: string): VerifiableCredentialDisplayBuilder {
    this.alt_text = text;
    return this;
  }

  withDescription(description: string): VerifiableCredentialDisplayBuilder {
    this.description = description;
    return this;
  }

  withBackgroundColor(color: string): VerifiableCredentialDisplayBuilder {
    this.background_color = color;
    return this;
  }

  withTextColor(textColor: string): VerifiableCredentialDisplayBuilder {
    this.text_color = textColor;
    return this;
  }

  build(): VerifiableCredentialDisplay {
    return {
      name: this.name,
      locale: this.locale,
      logo: this.logo,
      url: this.url,
      alt_text: this.alt_text,
      description: this.description,
      background_color: this.background_color,
      text_color: this.text_color
    }
  }
}