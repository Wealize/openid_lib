var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
/**
 * Abstract class that provided an interface to a VC Issuer
 * thorugh which it can get the information related to a VC
 */
export class CredentialDataManager {
    /**
     * Allows to obtain the true identifier of the credential subject. This method
     * can be overwritten if needed and can be useful when working with DID URL syntax
     * @param _accessTokenSubject The subject ID contained in an Access Token
     * @param proofIssuer The subject ID contained in a control proof
     * @returns
     */
    resolveCredentialSubject(_accessTokenSubject, proofIssuer) {
        return __awaiter(this, void 0, void 0, function* () {
            return proofIssuer;
        });
    }
}
