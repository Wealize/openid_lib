import { JWK } from "jose";
import { NonceState, NonceSpecificData, OperationTypeEnum } from "./types";
import { AuthzResponseType } from "../../common";
export declare class NonceStepBuilder {
    forIssuance(): NonceStepBuilderStageStep;
    forVerification(): NonceStepBuilderStageStep;
}
declare class NonceStepBuilderStageStep {
    private operationType;
    constructor(operationType: Extract<OperationTypeEnum, {
        type: string;
    }>["type"]);
    postBaseAuthz(redirectUri: string, responseType: Extract<AuthzResponseType, "id_token" | "vp_token">, holderState?: string, state?: string): NonceAuthorizationStepBuilder;
    postAuthz(redirectUri: string, responseType: Extract<AuthzResponseType, "id_token" | "vp_token">): NonceAuthorizationStepBuilder;
    challengeNonce(expirationTime: number): NonceBuilderEndStep;
}
declare class NonceAuthorizationStepBuilder {
    private operationType;
    private stageType;
    private redirectUri;
    private responseType;
    constructor(operationType: Extract<OperationTypeEnum, {
        type: string;
    }>["type"], stageType: Exclude<Extract<NonceSpecificData, {
        type: string;
    }>["type"], "ChallengeNonce" | "DirectRequest">, redirectUri: string, responseType: Extract<AuthzResponseType, "id_token" | "vp_token">);
    forHolderWallet(clientId: string): NonceHolderWalletStep;
    forServiceWallet(clientId: string): NonceServiceWalletStep;
}
declare class NonceHolderWalletStep {
    private operationType;
    private stageType;
    private redirectUri;
    private clientId;
    private responseType;
    constructor(operationType: Extract<OperationTypeEnum, {
        type: string;
    }>["type"], stageType: Exclude<Extract<NonceSpecificData, {
        type: string;
    }>["type"], "ChallengeNonce">, redirectUri: string, clientId: string, responseType: Extract<AuthzResponseType, "id_token" | "vp_token">);
    withCodeChallenge(codeChallenge: string, codeChallengeMethod: string): NonceBuilderEndStep;
    withoutCodeChallenge(): NonceBuilderEndStep;
}
declare class NonceServiceWalletStep {
    private operationType;
    private stageType;
    private redirectUri;
    private clientId;
    private responseType;
    constructor(operationType: Extract<OperationTypeEnum, {
        type: string;
    }>["type"], stageType: Exclude<Extract<NonceSpecificData, {
        type: string;
    }>["type"], "ChallengeNonce">, redirectUri: string, clientId: string, responseType: Extract<AuthzResponseType, "id_token" | "vp_token">);
    withJwk(jwk: JWK): NonceBuilderEndStep;
}
declare class NonceBuilderEndStep {
    private nonce;
    private operationType;
    constructor(nonce: NonceSpecificData, operationType: Extract<OperationTypeEnum, {
        type: string;
    }>["type"]);
    buildForSubject(sub: string): NonceState;
}
export {};
