import { InternalError } from "../../common/classes/index.js";
import { W3CVerifiableCredentialFormats } from "../../common/formats/index.js";
import { W3CVerifiableCredential } from "../../common/interfaces/w3c_verifiable_credential.interface.js";
import { JwtPayload } from "jsonwebtoken";

export abstract class VcFormatter {
  abstract formatVc(vc: W3CVerifiableCredential): W3CVerifiableCredential | JwtPayload;

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
