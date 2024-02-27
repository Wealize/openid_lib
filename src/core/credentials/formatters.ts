import { InternalError } from "../../common/classes/index.js";
import {
  W3CDataModel,
  W3CVerifiableCredentialFormats
} from "../../common/formats/index.js";
import {
  W3CVerifiableCredential,
} from "../../common/interfaces/w3c_verifiable_credential.interface.js";
import { JwtPayload } from "jsonwebtoken";

/**
 * Abstract class allowing to express unsigned W3C credentials in different formats.
 */
export abstract class VcFormatter {
  constructor(protected dataModel: W3CDataModel) { }
  /**
   * Express the specified VC in the format associated with the object
   * @param vc The VC to format.
   * @returns THe VC formated in W3C format or as a JWT payload
   */
  abstract formatVc(
    vc: W3CVerifiableCredential
  ): W3CVerifiableCredential | JwtPayload;


  /**
   * Generates a formatter instance based on the specified format
   * @param format The format to consider
   * @param dataModel The W3C data model version 
   * @returns A VcFormatter that allow to express unsigned VC in the specified format
   */
  static fromVcFormat(
    format: W3CVerifiableCredentialFormats,
    dataModel: W3CDataModel
  ): VcFormatter {
    if (format === "jwt_vc" || format === "jwt_vc_json") {
      return new JwtVcFormatter(dataModel);
    } else if (format === "jwt_vc_json-ld" || format === "ldp_vc") {
      // TODO:
      throw new InternalError("Unimplemented");
    } else {
      throw new InternalError("Unsupported format");
    }
  }

  /**
   * Generates a format that allow to express VC in JWT format
   * @returns A VcFormatter
   */
  static jwtFormatter(dataModel: W3CDataModel): JwtVcFormatter {
    return new JwtVcFormatter(dataModel);
  }
}

class JwtVcFormatter extends VcFormatter {
  formatVc(vc: W3CVerifiableCredential): W3CVerifiableCredential | JwtPayload {
    const token: JwtPayload = {
      sub: vc.credentialSubject.id,
      iss: vc.issuer,
      vc
    };
    if (this.dataModel === W3CDataModel.V1) {
      return this.formatDataModel1(token, vc)
    } else {
      return this.formatDataModel2(token, vc)
    }
  }

  private formatDataModel1(
    token: JwtPayload,
    vc: W3CVerifiableCredential
  ): W3CVerifiableCredential | JwtPayload {
    if (vc.issuanceDate) {
      token.iat = Date.parse(vc.validFrom!);
      token.nbf = Date.parse(vc.validFrom!);
    }
    if (vc.expirationDate) {
      token.exp = Date.parse(vc.validUntil);
    }
    return token;
  }

  private formatDataModel2(
    token: JwtPayload,
    vc: W3CVerifiableCredential
  ): W3CVerifiableCredential | JwtPayload {
    if (vc.validFrom) {
      token.iat = Date.parse(vc.validFrom!);
      token.nbf = Date.parse(vc.validFrom!);
    }
    if (vc.validUntil) {
      token.exp = Date.parse(vc.validUntil);
    }
    return token;
  }

}
