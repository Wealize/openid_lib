import { v4 as uuidv4 } from 'uuid';
import fetch from 'node-fetch';
import { verifyChallenge } from 'pkce-challenge';
import { Resolver } from 'did-resolver';
import { decodeToken, verifyJwtWithExpAndAudience, } from '../../common/utils/jwt.utils.js';
import { AUTHZ_TOKEN_EXPIRATION_TIME, DEFAULT_SCOPE, OPENID_CREDENTIAL_AUTHZ_DETAILS_TYPE, } from '../../common/constants/index.js';
import { IdTokenRequest, } from '../../common/classes/id_token_request.js';
import { getAuthentificationJWKKeys } from '../../common/utils/did_document.js';
import { AccessDenied, InsufficienteParamaters, InternalNonceError, InvalidGrant, InvalidRequest, InvalidScope, OpenIdError, UnauthorizedClient, UnsupportedGrantType, } from '../../common/classes/index.js';
import { VpResolver } from '../presentations/vp-resolver.js';
import { VpTokenRequest, } from '../../common/classes/vp_token_request.js';
import { P, match } from 'ts-pattern';
import { Result } from '../../common/classes/result.js';
import { NonceManager } from '../nonce/index.js';
/**
 * Represents an entity acting as a Reliying Party. As such, it has the
 * capability to process authorisation requests and to send others.
 * It can also issue access tokens.
 *
 * The "grant_type" "authorisation_code" and "pre-authorised_code" are supported
 * for authentication. The first one is always active. In order to facilitate the
 * building of the objects from this class, a builder has been developed.
 */
export class OpenIDReliyingParty {
    defaultHolderMetadata;
    metadata;
    didResolver;
    signCallback;
    scopeVerificationFlag;
    subjectComparison;
    generalConfiguration;
    issuerStateVerirication;
    authzDetailsVerification;
    vpCredentialVerificationCallback;
    preAuthCallback;
    nonceManager;
    /**
     * @param defaultHolderMetadata Default metadata configuration for all Holder Wallets
     * that establish contact. This configuration is overwritten dynamically with the
     * data provided by these actors.
     * @param metadata Authorisation server metadata
     * @param didResolver Object responsible for obtaining the DID Documents
     * of the DIDs that are detected.
     * @param signCallback Callback used to sign any required data.
     * @param scopeVerificationFlag Flag that control if the scope parameter
     * should be checked against the "scopes_supported" params of the Auth server
     * metadata
     * @param stateManager: An implementation of a State Manager that will be used to
     * store and control the lifetime of the nonces
     * @param subjectComparison Function used to compare if two ID, most probably DIDs,
     * are the same
     * @param generalConfiguration Configuration about the different expiration times
     * of the involved tokens
     * @param issuerStateVerirication Optional callback that can be used to check the "issuer state"
     * parameter, but only is provided
     * @param authzDetailsVerification Optional callback that can be used to check
     * the authorization details of a Authz Request, but only if provided
     * @param vpCredentialVerificationCallback Optional callback that is used during
     * VP verification to check the credential data agains the use case logic.
     * @param preAuthCallback Optional callback that is used to check the validity
     * of a Pre-Authorization Code
     */
    constructor(defaultHolderMetadata, metadata, didResolver, signCallback, scopeVerificationFlag, stateManager, subjectComparison, generalConfiguration, issuerStateVerirication, authzDetailsVerification, vpCredentialVerificationCallback, preAuthCallback) {
        this.defaultHolderMetadata = defaultHolderMetadata;
        this.metadata = metadata;
        this.didResolver = didResolver;
        this.signCallback = signCallback;
        this.scopeVerificationFlag = scopeVerificationFlag;
        this.subjectComparison = subjectComparison;
        this.generalConfiguration = generalConfiguration;
        this.issuerStateVerirication = issuerStateVerirication;
        this.authzDetailsVerification = authzDetailsVerification;
        this.vpCredentialVerificationCallback = vpCredentialVerificationCallback;
        this.preAuthCallback = preAuthCallback;
        this.nonceManager = new NonceManager(stateManager);
    }
    /**
     * Allows to add support for a new DID Method
     * @param methodName DID Method name
     * @param resolver Object responsible for obtaining the DID Documents
     * related to the DID specified
     */
    addDidMethod(methodName, resolver) {
        const tmp = {};
        tmp[methodName] = resolver;
        this.didResolver = new Resolver({
            ...this.didResolver,
            ...tmp,
        });
    }
    /**
     * Allows to create a new Authorisation request in which an ID Token
     * is requested
     * @param clientAuthorizationEndpoint Endpoint of the authorisation
     * server of the client
     * @param audience "aud" parameter for the generated JWT.
     * @param redirectUri URI to which the client should deliver the
     * authorisation response to
     * @param requestPurpose Allows to specify if the end purpose of the token
     * is for a VC issuance or for a verification and also allows to set
     * a verified authz request.
     * @param additionalParameters Additional parameters that handle
     * issues related to the content of the ID Token.
     * @returns The ID Token Request
     */
    async createIdTokenRequest(clientAuthorizationEndpoint, audience, redirectUri, requestPurpose, additionalParameters) {
        additionalParameters = {
            ...{
                responseMode: 'direct_post',
                nonce: uuidv4(),
                scope: DEFAULT_SCOPE,
                expirationTime: this.generalConfiguration.idTokenExpirationTime,
            },
            ...additionalParameters,
        };
        const { nonce, state } = this.createNonceForPostBaseAuthz(requestPurpose, 'id_token', additionalParameters.state);
        const requestParams = {
            response_type: 'id_token',
            scope: additionalParameters.scope,
            redirect_uri: redirectUri,
            response_mode: additionalParameters.responseMode,
            nonce: nonce,
            client_id: this.metadata.issuer,
        };
        if (additionalParameters.state) {
            requestParams.state = additionalParameters.state;
        }
        const idToken = await this.signCallback({
            aud: audience,
            iss: this.metadata.issuer,
            exp: state.timestamp + additionalParameters.expirationTime,
            ...requestParams,
            ...additionalParameters.additionalPayload,
        }, this.metadata.request_object_signing_alg_values_supported);
        await this.nonceManager.saveNonce(nonce, state);
        return new IdTokenRequest(requestParams, idToken, clientAuthorizationEndpoint);
    }
    /**
     * Method that allows to build an VP Token Request directly, without
     * the need of a previous Base Authz Request
     * @param presentationDefinition The presentation definition to indicate to
     * the user
     * @param additionalParameters Additional parameters that handle
     * issues related to the content of the VP Token.
     * @returns A VP Token Request
     */
    async directVpTokenRequestForVerification(presentationDefinition, redirectUri, additionalParameters) {
        // TODO: Refactor this method in the future. Too similar to createVpTokenRequest
        additionalParameters = {
            ...{
                responseMode: 'direct_post',
                scope: DEFAULT_SCOPE,
                expirationTime: this.generalConfiguration.vpTokenExpirationTIme,
            },
            ...additionalParameters,
        };
        const nonceState = {
            type: 'DirectRequest',
            operationType: {
                type: 'Verification',
                scope: additionalParameters.scope,
            },
            responseType: 'vp_token',
            timestamp: Date.now(),
            sub: 'https://self-issued.me/v2',
        };
        const nonce = uuidv4();
        const requestParams = {
            response_type: 'vp_token',
            scope: additionalParameters.scope,
            redirect_uri: redirectUri,
            response_mode: additionalParameters.responseMode,
            nonce: nonce,
            client_id: this.metadata.issuer,
        };
        if (additionalParameters.state) {
            requestParams.state = additionalParameters.state;
        }
        match(presentationDefinition)
            .with({ type: 'Raw' }, data => (requestParams.presentation_definition = data.presentationDefinition))
            .with({ type: 'Uri' }, data => (requestParams.presentation_definition_uri =
            data.presentationDefinitionUri))
            .exhaustive();
        const vpToken = await this.signCallback({
            aud: 'https://self-issued.me/v2',
            iss: this.metadata.issuer,
            exp: nonceState.timestamp + additionalParameters.expirationTime,
            ...requestParams,
            ...additionalParameters.additionalPayload,
        }, this.metadata.request_object_signing_alg_values_supported);
        await this.nonceManager.saveNonce(nonce, nonceState);
        return new VpTokenRequest(requestParams, vpToken, '');
    }
    /**
     * Allows to create a new Authorisation request in which an VP Token
     * is requested
     * @param clientAuthorizationEndpoint Endpoint of the authorisation
     * server of the client
     * @param audience "aud" parameter for the generated JWT.
     * @param redirectUri URI to which the client should deliver the
     * authorisation response to
     * @param presentationDefinition Allows to define how the presentation
     * definition is going to be specified for the user
     * @param requestPurpose Allows to specify if the end purpose of the token
     * is for a VC issuance or for a verification and also allows to set
     * a verified authz request.
     * @param additionalParameters Additional parameters that handle
     * issues related to the content of the VP Token.
     * @returns The VP Token Request
     */
    async createVpTokenRequest(clientAuthorizationEndpoint, audience, redirectUri, presentationDefinition, requestPurpose, additionalParameters) {
        additionalParameters = {
            ...{
                responseMode: 'direct_post',
                scope: DEFAULT_SCOPE,
                expirationTime: this.generalConfiguration.vpTokenExpirationTIme,
            },
            ...additionalParameters,
        };
        const { nonce, state } = this.createNonceForPostBaseAuthz(requestPurpose, 'vp_token', additionalParameters.state);
        const requestParams = {
            response_type: 'vp_token',
            scope: additionalParameters.scope,
            redirect_uri: redirectUri,
            response_mode: additionalParameters.responseMode,
            nonce: nonce,
            client_id: this.metadata.issuer,
        };
        if (additionalParameters.state) {
            requestParams.state = additionalParameters.state;
        }
        match(presentationDefinition)
            .with({ type: 'Raw' }, data => (requestParams.presentation_definition = data.presentationDefinition))
            .with({ type: 'Uri' }, data => (requestParams.presentation_definition_uri =
            data.presentationDefinitionUri))
            .exhaustive();
        const vpToken = await this.signCallback({
            aud: audience,
            iss: this.metadata.issuer,
            exp: state.timestamp + additionalParameters.expirationTime,
            ...requestParams,
            ...additionalParameters.additionalPayload,
        }, this.metadata.request_object_signing_alg_values_supported);
        await this.nonceManager.saveNonce(nonce, state);
        return new VpTokenRequest(requestParams, vpToken, clientAuthorizationEndpoint);
    }
    createNonceForPostBaseAuthz(purpose, responseType, state) {
        const nonceState = match(purpose)
            .with({ type: 'Issuance' }, data => {
            let vcTypes = {
                type: 'Uknown',
            };
            for (const details of purpose.verifiedBaseAuthzRequest.authzRequest
                .authorization_details) {
                // TODO: Revise this. Search for a better way to do it.
                if (details.type === OPENID_CREDENTIAL_AUTHZ_DETAILS_TYPE) {
                    vcTypes = {
                        type: 'Know',
                        vcTypes: details.types,
                    };
                    break;
                }
            }
            if (data.verifiedBaseAuthzRequest.serviceWalletJWK) {
                return {
                    type: 'PostBaseAuthz',
                    timestamp: Date.now(),
                    sub: data.verifiedBaseAuthzRequest.authzRequest.client_id,
                    redirectUri: data.verifiedBaseAuthzRequest.authzRequest.redirect_uri,
                    responseType: responseType,
                    state,
                    holderState: data.verifiedBaseAuthzRequest.authzRequest.state,
                    clientData: {
                        type: 'ServiceWallet',
                        clientId: data.verifiedBaseAuthzRequest.authzRequest.client_id,
                        clientJwk: data.verifiedBaseAuthzRequest.serviceWalletJWK,
                    },
                    operationType: {
                        type: 'Issuance',
                        vcTypes: vcTypes,
                    },
                };
            }
            if (!data.verifiedBaseAuthzRequest.authzRequest.code_challenge ||
                !data.verifiedBaseAuthzRequest.authzRequest.code_challenge_method) {
                throw new InvalidRequest('A code_challenge is required');
            }
            return {
                type: 'PostBaseAuthz',
                timestamp: Date.now(),
                sub: data.verifiedBaseAuthzRequest.authzRequest.client_id,
                redirectUri: data.verifiedBaseAuthzRequest.authzRequest.redirect_uri,
                responseType: responseType,
                state,
                holderState: data.verifiedBaseAuthzRequest.authzRequest.state,
                clientData: {
                    type: 'HolderWallet',
                    clientId: data.verifiedBaseAuthzRequest.authzRequest.client_id,
                    codeChallenge: data.verifiedBaseAuthzRequest.authzRequest.code_challenge, // TODO: CHECK CODE CHALLENGE AND ERASE FORM AUTHZ
                    codeChallengeMethod: data.verifiedBaseAuthzRequest.authzRequest.code_challenge_method,
                },
                operationType: {
                    type: 'Issuance',
                    vcTypes: vcTypes,
                },
            };
        })
            .with({ type: 'Verification' }, data => {
            if (data.verifiedBaseAuthzRequest.serviceWalletJWK) {
                return {
                    type: 'PostBaseAuthz',
                    operationType: {
                        type: 'Verification',
                        scope: data.verifiedBaseAuthzRequest.authzRequest.scope,
                    },
                    clientData: {
                        type: 'HolderWallet',
                        clientId: data.verifiedBaseAuthzRequest.authzRequest.client_id,
                    },
                    timestamp: Date.now(),
                    holderState: data.verifiedBaseAuthzRequest.authzRequest.state,
                    sub: data.verifiedBaseAuthzRequest.authzRequest.client_id,
                    redirectUri: data.verifiedBaseAuthzRequest.authzRequest.redirect_uri,
                    responseType: responseType,
                };
            }
            return {
                type: 'PostBaseAuthz',
                operationType: {
                    type: 'Verification',
                    scope: data.verifiedBaseAuthzRequest.authzRequest.scope,
                },
                clientData: {
                    type: 'ServiceWallet',
                    clientJwk: data.verifiedBaseAuthzRequest.serviceWalletJWK,
                    clientId: data.verifiedBaseAuthzRequest.authzRequest.client_id,
                },
                timestamp: Date.now(),
                holderState: data.verifiedBaseAuthzRequest.authzRequest.state,
                sub: data.verifiedBaseAuthzRequest.authzRequest.client_id,
                redirectUri: data.verifiedBaseAuthzRequest.authzRequest.redirect_uri,
                responseType: responseType,
            };
        })
            .exhaustive();
        return { nonce: uuidv4(), state: nonceState };
    }
    /**
     * Allows to verify an authorisation request sent by a client
     * @param request The request sent by the client
     * @returns Verified Authz Reques with some of the client metadata extracted
     */
    async verifyBaseAuthzRequest(request) {
        // TODO: RESPONSE MODE SHOULD BE CHECKED
        let params;
        let jwk = undefined;
        if (!request.request) {
            params = request;
        }
        else {
            // TODO: ADD REQUEST_URI PARAMETER
            if (this.metadata.request_parameter_supported === false) {
                throw new InvalidRequest('Unsuported request parameter');
            }
            const { header, payload } = decodeToken(request.request);
            if (this.metadata.request_object_signing_alg_values_supported &&
                !this.metadata.request_object_signing_alg_values_supported.includes(header.alg)) {
                throw new InvalidRequest('Unsuported request signing alg');
            }
            params = payload;
            if (!params.client_metadata ||
                'jwks_uri' in params.client_metadata === false) {
                throw new InvalidRequest('Expected client metadata with jwks_uri');
            }
            const keys = await fetchJWKs(params.client_metadata.jwks_uri);
            if (!header.kid) {
                throw new InvalidRequest('No kid specify in JWT header');
            }
            jwk = selectJwkFromSet(keys, header.kid);
            try {
                await verifyJwtWithExpAndAudience(request.request, jwk, this.metadata.issuer);
            }
            catch (error) {
                throw new InvalidRequest(error.message);
            }
        }
        params.client_metadata = await this.resolveClientMetadata(params.client_metadata);
        const validatedClientMetadata = this.validateClientMetadata(params.client_metadata);
        if (this.scopeVerificationFlag) {
            if (this.metadata.scopes_supported &&
                !this.metadata.scopes_supported.includes(params.scope)) {
                throw new InvalidScope(`Invalid scope specified: ${params.scope}`);
            }
        }
        if (params.authorization_details) {
            for (const details of params.authorization_details) {
                if (details.locations &&
                    details.locations.length &&
                    !details.locations.includes(this.metadata.issuer)) {
                    throw new InvalidRequest('Location must contains Issuer client id value');
                }
                if (this.authzDetailsVerification) {
                    const authDetailsVerificationResult = await this.authzDetailsVerification(details);
                    if (authDetailsVerificationResult.isError()) {
                        throw new InvalidRequest('Invalid authorization details specified ' +
                            authDetailsVerificationResult.unwrapError());
                    }
                }
            }
        }
        if (this.issuerStateVerirication) {
            if (!params.issuer_state) {
                throw new InvalidRequest('An "issuer_state" parameter is required');
            }
            const issuerStateVerificationResult = await this.issuerStateVerirication(params.issuer_state);
            if (issuerStateVerificationResult.isError()) {
                throw new InvalidRequest('Invalid "issuer_state" provided' +
                    issuerStateVerificationResult.unwrapError());
            }
        }
        return {
            validatedClientMetadata,
            authzRequest: params,
            serviceWalletJWK: jwk,
        };
    }
    createNonceForPostAuthz(nonceValue, baseAuthzNonce, subject) {
        return {
            nonce: nonceValue,
            state: {
                ...baseAuthzNonce,
                type: 'PostAuthz',
                sub: subject,
            },
        };
    }
    async checkNonceStateForPostBaseAuthz(nonce, subject, expectedResponseType, state) {
        let nonceState;
        let redirectUri, holderState;
        const nonceResult = await this.nonceManager.getPostBaseAuthzNonce(nonce);
        if (nonceResult.isError()) {
            const nonceResult = await this.nonceManager.getDirectRequestNonce(nonce);
            if (nonceResult.isError()) {
                throw new InvalidRequest('Invalid nonce specified');
            }
            await this.nonceManager.deleteNonce(nonce);
            nonceState = nonceResult.unwrap();
            redirectUri = undefined;
            holderState = undefined;
        }
        else {
            const prevNonce = nonceResult.unwrap();
            if (prevNonce.responseType !== expectedResponseType) {
                throw new InvalidRequest(`Unexpected response type. An ${expectedResponseType} was expected.`);
            }
            match(prevNonce.clientData).with({ type: 'HolderWallet' }, data => {
                if (!this.subjectComparison(data.clientId, subject)) {
                    throw new InvalidRequest('The iss parameter does not coincide with the previously stated client id');
                }
            });
            if (prevNonce.state && prevNonce.state !== state) {
                throw new InvalidRequest('Invalid state parameter');
            }
            nonceState = prevNonce;
            redirectUri = prevNonce.redirectUri;
            holderState = prevNonce.holderState;
        }
        return {
            nonceState: nonceState,
            redirectUri,
            holderState,
        };
    }
    /**
     * Allows to verify an ID Token Response sent by a client
     * @param idTokenResponse The authorisation response to verify
     * @returns The verified ID Token Response with the DID Document of the
     * associated token issuer.
     * @throws If data provided is incorrect
     */
    async verifyIdTokenResponse(idTokenResponse, checkTokenSignature = true) {
        const { header, payload } = decodeToken(idTokenResponse.id_token);
        const jwtPayload = payload;
        if (!jwtPayload.iss) {
            throw new InvalidRequest("Id Token must contain 'iss' atribute");
        }
        if (!jwtPayload.nonce) {
            throw new InvalidRequest('No nonce paramater found in ID Token');
        }
        const { nonceState, redirectUri, holderState } = await this.checkNonceStateForPostBaseAuthz(jwtPayload.nonce, jwtPayload.iss, 'id_token', jwtPayload.state);
        if (!jwtPayload.sub) {
            throw new InvalidRequest("Id Token must contain 'sub' atribute", redirectUri, holderState);
        }
        if (!header.kid) {
            throw new InvalidRequest('No kid paramater found in ID Token', redirectUri, holderState);
        }
        if (this.metadata.id_token_signing_alg_values_supported &&
            !this.metadata.id_token_signing_alg_values_supported.includes(header.alg)) {
            throw new InvalidRequest('Unsuported signing alg for ID Token', redirectUri, holderState);
        }
        let didDocument = undefined;
        try {
            if (checkTokenSignature) {
                const didResolution = await this.didResolver.resolve(jwtPayload.iss);
                if (didResolution.didResolutionMetadata.error) {
                    throw new UnauthorizedClient(`Did resolution failed. Error ${didResolution.didResolutionMetadata.error}: ${didResolution.didResolutionMetadata.message}`, redirectUri, holderState);
                }
                didDocument = didResolution.didDocument;
                const publicKeyJwk = getAuthentificationJWKKeys(didDocument, header.kid);
                await verifyJwtWithExpAndAudience(idTokenResponse.id_token, publicKeyJwk, this.metadata.issuer);
            }
            else {
                if (!jwtPayload.exp || jwtPayload.exp < Math.floor(Date.now() / 1000)) {
                    throw new InvalidRequest('JWT is expired or does not have exp parameter', redirectUri, holderState);
                }
                if (!jwtPayload.aud || jwtPayload.aud !== this.metadata.issuer) {
                    throw new InvalidRequest('JWT audience is invalid or is not defined', redirectUri, holderState);
                }
            }
        }
        catch (error) {
            throw new AccessDenied(error.message, redirectUri, holderState);
        }
        const { authzCode } = await this.processNonceForPostAuthz(nonceState, jwtPayload.nonce, jwtPayload.iss);
        return {
            token: idTokenResponse.id_token,
            didDocument,
            subject: jwtPayload.sub,
            authzCode,
            state: holderState,
            redirectUri: redirectUri,
        };
    }
    /**
     * Allows to verify an VP Token Response sent by a client
     * @param vpTokenResponse The authorisation response to verify
     * @param presentationDefinition The presentation definition to use to
     * verify the VP
     * @param vcSignatureVerification A flag that can be used to specify if the signature
     * of the VC should be checked. True by default
     * @returns The verified VP Token Response with holder DID and the data
     * extracted from the VCs of the VP
     * @throws If data provided is incorrect
     */
    async verifyVpTokenResponse(vpTokenResponse, presentationDefinition, // TODO: Convert this to a callback
    vcSignatureVerification = true) {
        if (!this.vpCredentialVerificationCallback) {
            throw new InternalNonceError('An VP Credential Verification callback must be provided in order to verify VPs');
        }
        let nonceState = undefined;
        let redirectUri, holderState = undefined;
        let clientId;
        let nonceValue;
        try {
            const vpResolver = new VpResolver(this.didResolver, this.metadata.issuer, this.vpCredentialVerificationCallback, async (subject, nonce, state) => {
                nonceValue = nonce;
                // TODO: Update this
                const tmp = await this.checkNonceStateForPostBaseAuthz(nonce, subject, 'vp_token', state);
                nonceState = tmp.nonceState;
                redirectUri = tmp.redirectUri;
                holderState = tmp.holderState;
                clientId = subject;
                return Result.Ok(null);
            }, vcSignatureVerification);
            const claimData = await vpResolver.verifyPresentation(vpTokenResponse.vp_token, presentationDefinition, vpTokenResponse.presentation_submission);
            const { authzCode } = await this.processNonceForPostAuthz(nonceState, nonceValue, clientId);
            return {
                token: vpTokenResponse.vp_token,
                vpInternalData: claimData,
                authzCode,
                state: holderState,
                redirectUri: redirectUri,
            };
        }
        catch (e) {
            if (e instanceof OpenIdError) {
                if (nonceState) {
                    e.redirectUri = redirectUri;
                    e.holderState = holderState;
                }
            }
            throw e;
        }
    }
    async processNonceForPostAuthz(prevNonce, nonceValue, clientId) {
        return match(prevNonce)
            .with({ type: 'PostBaseAuthz' }, async (data) => {
            const { nonce, state } = this.createNonceForPostAuthz(nonceValue, data, clientId);
            if (data.operationType.type === 'Issuance') {
                await this.nonceManager.updateNonce(nonce, state);
            }
            return {
                authzCode: await this.signCallback({
                    aud: this.metadata.issuer,
                    iss: this.metadata.issuer,
                    sub: clientId, // TODO: This maybe needs to be the URI of the ServiceWallet
                    exp: Date.now() + AUTHZ_TOKEN_EXPIRATION_TIME * 1000, // TODO: Set configurable the exp time
                    nonce: nonce,
                }),
                holderState: data.holderState,
                redirectUri: data.redirectUri,
            };
        })
            .otherwise(() => {
            return {
                authzCode: undefined,
                holderState: undefined,
                redirectUri: undefined,
            };
        });
    }
    generateCNonce(now, subject, exp, nonceValue, prevNonce) {
        let operationType;
        if (prevNonce) {
            operationType = prevNonce.operationType;
        }
        else {
            operationType = {
                type: 'Issuance',
                vcTypes: {
                    type: 'Uknown',
                },
            };
        }
        const nonceState = {
            type: 'ChallengeNonce',
            expirationTime: exp,
            timestamp: now,
            sub: subject,
            operationType: operationType,
        };
        return { nonce: nonceValue ?? uuidv4(), state: nonceState };
    }
    /**
     * Allows to generate a token response from a token request
     * @param tokenRequest The token request sent by the client
     * @param generateIdToken Flag indicating whether, together with
     * the access token, an ID Token should be generated.
     * @param tokenSignCallback Callback that manages the signature of the token.
     * @param audience JWT "aud" to include in the generated access token
     * @param authServerPublicKeyJwk The JWK used by the authServer to verify
     * the authz code
     * @returns Token response with the generated access token
     * @throws If data provided is incorrect
     */
    async generateAccessToken(tokenRequest, generateIdToken, audience, authServerPublicKeyJwk) {
        let clientId;
        let prevNonce;
        let nonceValue;
        let additionalParams = {};
        if (this.metadata.grant_types_supported &&
            !this.metadata.grant_types_supported.includes(tokenRequest.grant_type)) {
            throw new UnsupportedGrantType(`Grant type "${tokenRequest.grant_type}" not supported`);
        }
        switch (tokenRequest.grant_type) {
            case 'authorization_code': {
                if (!tokenRequest.code) {
                    throw new InvalidGrant(`Grant type "${tokenRequest.grant_type}" invalid parameters`);
                }
                await verifyJwtWithExpAndAudience(tokenRequest.code, authServerPublicKeyJwk, this.metadata.issuer);
                const { payload } = decodeToken(tokenRequest.code);
                const jwtPayload = payload;
                const nonceResult = await this.nonceManager.getPostAuthz(jwtPayload.nonce);
                nonceValue = jwtPayload.nonce;
                if (nonceResult.isError()) {
                    throw new InvalidGrant('Invalid authorization code provided');
                }
                prevNonce = nonceResult.unwrap();
                await match(prevNonce.clientData)
                    .with({ type: 'HolderWallet' }, async (data) => {
                    // TODO: Give an use to the code_challenge_method parameter
                    if (!(await verifyChallenge(tokenRequest.code_verifier, data.codeChallenge))) {
                        throw new InvalidRequest('The code_verifier does not verify the challenge provided');
                    }
                    if (!this.subjectComparison(data.clientId, jwtPayload.sub)) {
                        throw new InvalidRequest('The token was issued for a diferent client id');
                    }
                    // if (data.clientId !== jwtPayload.sub) {
                    //   throw new InvalidRequest("The token was issued for a diferent client id");
                    // }
                })
                    .with({ type: 'ServiceWallet' }, async (data) => {
                    if (tokenRequest.client_assertion_type &&
                        tokenRequest.client_assertion_type ===
                            'urn:ietf:params:oauth:client-assertion-type:jwt-bearer') {
                        if (!tokenRequest.client_assertion) {
                            throw new InvalidRequest('No "client_assertion" was provided');
                        }
                        if (data.clientId !== tokenRequest.client_id) {
                            throw new InvalidRequest('The client ID specified does not coincide with the previously provided');
                        }
                        await verifyJwtWithExpAndAudience(tokenRequest.client_assertion, data.clientJwk, this.metadata.issuer);
                    }
                })
                    .exhaustive();
                await match(prevNonce.operationType)
                    .with({ type: 'Issuance', vcTypes: { type: 'Know', vcTypes: P.select() } }, async (types) => {
                    additionalParams = { vc_types: types };
                })
                    .with({ type: 'Verification' }, async (data) => {
                    additionalParams = { verification_scope: data.scope };
                });
                clientId = jwtPayload.sub; // This should be a DID
                break;
            }
            case 'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
                if (!tokenRequest['pre-authorized_code']) {
                    throw new InvalidGrant(`Grant type "${tokenRequest.grant_type}" invalid parameters`);
                }
                if (!this.preAuthCallback) {
                    throw new InsufficienteParamaters(`No verification callback was provided for "${tokenRequest.grant_type}" grant type`);
                }
                const verificationResultPre = await this.preAuthCallback(tokenRequest.client_id, tokenRequest['pre-authorized_code'], tokenRequest.user_pin);
                if (verificationResultPre.isError()) {
                    throw new InvalidGrant(`Invalid "${tokenRequest.grant_type}" provided ${verificationResultPre.unwrapError().message}`);
                }
                clientId = verificationResultPre.unwrap();
                if (tokenRequest.user_pin) {
                    additionalParams = { pin: tokenRequest.user_pin };
                }
                break;
            }
            case 'vp_token': {
                // TODO: PENDING
                if (!tokenRequest.vp_token) {
                    throw new InsufficienteParamaters('Grant type "vp_token" requires the "vp_token" parameter');
                }
                throw new InternalNonceError('Uninplemented');
            }
        }
        const now = Date.now();
        const { nonce, state } = this.generateCNonce(now, clientId, this.generalConfiguration.cNonceExpirationTime * 1000, nonceValue, prevNonce);
        const token = await this.signCallback({
            aud: audience,
            iss: this.metadata.issuer,
            sub: clientId,
            exp: now + this.generalConfiguration.accessTokenExpirationTime * 1000,
            nonce: nonce,
            ...additionalParams,
        });
        if (prevNonce) {
            await this.nonceManager.updateNonce(nonce, state);
        }
        else {
            await this.nonceManager.saveNonce(nonce, state);
        }
        const result = {
            access_token: token,
            token_type: 'bearer',
            expires_in: this.generalConfiguration.accessTokenExpirationTime,
            c_nonce: nonce,
            c_nonce_expires_in: this.generalConfiguration.cNonceExpirationTime,
        };
        if (generateIdToken) {
            result.id_token = await this.signCallback({
                iss: this.metadata.issuer,
                sub: clientId,
                exp: now + this.generalConfiguration.accessTokenExpirationTime * 1000,
            }, this.metadata.id_token_signing_alg_values_supported);
        }
        return result;
    }
    validateClientMetadata(clientMetadata) {
        const idTokenAlg = [];
        const vpFormats = {};
        if (this.metadata.id_token_signing_alg_values_supported &&
            clientMetadata.id_token_signing_alg_values_supported) {
            for (const alg of clientMetadata.id_token_signing_alg_values_supported) {
                if (this.metadata.id_token_signing_alg_values_supported.includes(alg)) {
                    idTokenAlg.push(alg);
                }
            }
        }
        if (this.metadata.vp_formats_supported) {
            for (const format in clientMetadata.vp_formats_supported) {
                if (this.metadata.vp_formats_supported[format]) {
                    const intersectArray = [];
                    for (const alg of clientMetadata.vp_formats_supported[format].alg_values_supported) {
                        if (this.metadata.vp_formats_supported[format]?.alg_values_supported.includes(alg)) {
                            intersectArray.push(alg);
                        }
                    }
                    vpFormats[format] = {
                        alg_values_supported: intersectArray,
                    };
                }
            }
        }
        return {
            responseTypesSupported: clientMetadata.response_types_supported ?? [],
            idTokenAlg,
            vpFormats,
            authorizationEndpoint: clientMetadata.authorization_endpoint,
        };
    }
    async resolveClientMetadata(metadata) {
        return metadata
            ? { ...this.defaultHolderMetadata, ...metadata }
            : this.defaultHolderMetadata;
    }
}
async function fetchJWKs(url) {
    try {
        const response = await fetch(url);
        const jwks = await response.json();
        if (!jwks.keys) {
            throw new InvalidRequest("No 'keys' paramater found");
        }
        return jwks['keys'];
    }
    catch (e) {
        throw new InternalNonceError(`Can't recover credential issuer JWKs: ${e}`);
    }
}
function selectJwkFromSet(jwks, kid) {
    const jwk = jwks.find(jwk => jwk.kid === kid);
    if (!jwk) {
        throw new InvalidRequest(`No JWK found with kid ${kid}`);
    }
    return jwk;
}
export * from './types.js';
export * from './builder.js';
//# sourceMappingURL=index.js.map