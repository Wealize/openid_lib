export class NonceStepBuilder {
    forIssuance() {
        return new NonceStepBuilderStageStep("Issuance");
    }
    forVerification() {
        return new NonceStepBuilderStageStep("Verification");
    }
}
class NonceStepBuilderStageStep {
    constructor(operationType) {
        this.operationType = operationType;
    }
    ;
    postBaseAuthz(redirectUri, responseType, holderState, state) {
        return new NonceAuthorizationStepBuilder(this.operationType, "PostBaseAuthz", redirectUri, responseType);
    }
    postAuthz(redirectUri, responseType) {
        return new NonceAuthorizationStepBuilder(this.operationType, "PostAuthz", redirectUri, responseType);
    }
    challengeNonce(expirationTime) {
        return new NonceBuilderEndStep({
            type: "ChallengeNonce",
            expirationTime,
        }, this.operationType);
    }
}
class NonceDirectRequestStepBuilder {
    constructor(operationType, stageType, responseType) {
        this.operationType = operationType;
        this.stageType = stageType;
        this.responseType = responseType;
    }
}
class NonceAuthorizationStepBuilder {
    constructor(operationType, stageType, redirectUri, responseType) {
        this.operationType = operationType;
        this.stageType = stageType;
        this.redirectUri = redirectUri;
        this.responseType = responseType;
    }
    forHolderWallet(clientId) {
        return new NonceHolderWalletStep(this.operationType, this.stageType, this.redirectUri, clientId, this.responseType);
    }
    forServiceWallet(clientId) {
        return new NonceServiceWalletStep(this.operationType, this.stageType, this.redirectUri, clientId, this.responseType);
    }
}
class NonceHolderWalletStep {
    constructor(operationType, stageType, redirectUri, clientId, responseType) {
        this.operationType = operationType;
        this.stageType = stageType;
        this.redirectUri = redirectUri;
        this.clientId = clientId;
        this.responseType = responseType;
    }
    withCodeChallenge(codeChallenge, codeChallengeMethod) {
        return new NonceBuilderEndStep({
            type: this.stageType,
            redirectUri: this.redirectUri,
            responseType: this.responseType,
            clientData: {
                type: "HolderWallet",
                clientId: this.clientId,
                codeChallenge,
                codeChallengeMethod,
            }
        }, this.operationType);
    }
    withoutCodeChallenge() {
        return new NonceBuilderEndStep({
            type: this.stageType,
            redirectUri: this.redirectUri,
            responseType: this.responseType,
            clientData: {
                type: "HolderWallet",
                clientId: this.clientId,
            }
        }, this.operationType);
    }
}
class NonceServiceWalletStep {
    constructor(operationType, stageType, redirectUri, clientId, responseType) {
        this.operationType = operationType;
        this.stageType = stageType;
        this.redirectUri = redirectUri;
        this.clientId = clientId;
        this.responseType = responseType;
    }
    withJwk(jwk) {
        return new NonceBuilderEndStep({
            type: this.stageType,
            redirectUri: this.redirectUri,
            responseType: this.responseType,
            clientData: {
                type: "ServiceWallet",
                clientId: this.clientId,
                clientJwk: jwk
            }
        }, this.operationType);
    }
}
class NonceBuilderEndStep {
    constructor(nonce, operationType) {
        this.nonce = nonce;
        this.operationType = operationType;
    }
    buildForSubject(sub) {
        return Object.assign(Object.assign({}, this.nonce), { timestamp: Date.now(), sub, operationType: this.operationType });
    }
}
