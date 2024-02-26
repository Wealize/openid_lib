import { InternalError } from "../../common/classes/index.js";
/**
 * Abstract class allowing to express unsigned W3C credentials in different formats.
 */
export class VcFormatter {
    /**
     * Generates a formatter instance based on the specified format
     * @param format The format to consider
     * @returns A VcFormatter that allow to express unsigned VC in the specified format
     */
    static fromVcFormat(format) {
        if (format === "jwt_vc" || format === "jwt_vc_json") {
            return new JwtVcFormatter();
        }
        else if (format === "jwt_vc_json-ld" || format === "ldp_vc") {
            // TODO:
            throw new InternalError("Unimplemented");
        }
        else {
            throw new InternalError("Unsupported format");
        }
    }
    /**
     * Generates a format that allow to express VC in JWT format
     * @returns A VcFormatter
     */
    static jwtFormatter() {
        return new JwtVcFormatter();
    }
}
class JwtVcFormatter extends VcFormatter {
    formatVc(vc) {
        const token = {
            sub: vc.credentialSubject.id,
            iss: vc.issuer,
            vc
        };
        if (vc.validFrom) {
            token.iat = Date.parse(vc.validFrom);
            token.nbf = Date.parse(vc.validFrom);
        }
        if (vc.validUntil) {
            token.exp = Date.parse(vc.validUntil);
        }
        return token;
    }
}
