import { InternalError } from "../../common/classes/index.js";
import { W3CVerifiableCredentialFormats } from "../../common/formats/index.js";
import {
  W3CVerifiableCredential
} from "../../common/interfaces/w3c_verifiable_credential.interface.js";
import { JwtPayload } from "jsonwebtoken";

/**
 * Abstract class allowing to express unsigned W3C credentials in different formats.
 */
export abstract class VcFormatter {
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
   * @returns A VcFormatter that allow to express unsigned VC in the specified format
   */
  static fromVcFormat(format: W3CVerifiableCredentialFormats): VcFormatter {
    if (format === "jwt_vc" || format === "jwt_vc_json") {
      return new JwtVcFormatter();
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
  static jwtFormatter(): JwtVcFormatter {
    return new JwtVcFormatter();
  }
}

class JwtVcFormatter extends VcFormatter {
  formatVc(vc: W3CVerifiableCredential): W3CVerifiableCredential | JwtPayload {
    const token: JwtPayload = {
      sub: vc.credentialSubject.id,
      iss: vc.issuer,
      vc
    };
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
