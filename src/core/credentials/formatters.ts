import { W3CVerifiableCredentialFormats } from "common/formats";
import { W3CVerifiableCredential } from "common/interfaces/w3c_verifiable_credential.interface";
import { JwtPayload } from "jsonwebtoken";

export abstract class VcFormatter {
  abstract formatVc(vc: W3CVerifiableCredential): W3CVerifiableCredential | JwtPayload;

  static fromVcFormat(format: W3CVerifiableCredentialFormats): VcFormatter {
    if (format === "jwt_vc" || format === "jwt_vc_json") {
      return new JwtVcFormatter();
    } else if (format === "jwt_vc_json-ld" || format === "ldp_vc") {
      // TODO:
      throw new Error("Unimplemented");
    } else {
      throw new Error("Unsupported format");

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
