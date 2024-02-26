import { W3CVerifiableCredentialFormats } from "../../common/formats/index.js";
import { W3CVerifiableCredential } from "../../common/interfaces/w3c_verifiable_credential.interface.js";
import { JwtPayload } from "jsonwebtoken";
/**
 * Abstract class allowing to express unsigned W3C credentials in different formats.
 */
export declare abstract class VcFormatter {
    /**
     * Express the specified VC in the format associated with the object
     * @param vc The VC to format.
     * @returns THe VC formated in W3C format or as a JWT payload
     */
    abstract formatVc(vc: W3CVerifiableCredential): W3CVerifiableCredential | JwtPayload;
    /**
     * Generates a formatter instance based on the specified format
     * @param format The format to consider
     * @returns A VcFormatter that allow to express unsigned VC in the specified format
     */
    static fromVcFormat(format: W3CVerifiableCredentialFormats): VcFormatter;
    /**
     * Generates a format that allow to express VC in JWT format
     * @returns A VcFormatter
     */
    static jwtFormatter(): JwtVcFormatter;
}
declare class JwtVcFormatter extends VcFormatter {
    formatVc(vc: W3CVerifiableCredential): W3CVerifiableCredential | JwtPayload;
}
export {};
