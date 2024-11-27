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
    async resolveCredentialSubject(_accessTokenSubject, proofIssuer) {
        return proofIssuer;
    }
}
//# sourceMappingURL=credential_data_manager.js.map