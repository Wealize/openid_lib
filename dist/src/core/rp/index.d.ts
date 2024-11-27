import { JWK } from 'jose';
import { Resolvable, Resolver } from 'did-resolver';
import { AuthServerMetadata } from '../../common/interfaces/auth_server_metadata.interface.js';
import { AuthzRequestWithJWT } from '../../common/interfaces/authz_request.interface.js';
import { HolderMetadata } from '../../common/interfaces/client_metadata.interface.js';
import { IdTokenRequest } from '../../common/classes/id_token_request.js';
import { IdTokenResponse } from '../../common/interfaces/id_token_response.js';
import { TokenRequest } from '../../common/interfaces/token_request.interface.js';
import { TokenResponse } from '../../common/interfaces/token_response.interface.js';
import * as RpTypes from './types.js';
import { AuthorizationDetails, DIFPresentationDefinition, VpTokenResponse } from '../../common/index.js';
import { VpTokenRequest } from '../../common/classes/vp_token_request.js';
import { CredentialAdditionalVerification } from '../presentations/types.js';
import { Result } from '../../common/classes/result.js';
import { StateManager } from '../state/index.js';
/**
 * Represents an entity acting as a Reliying Party. As such, it has the
 * capability to process authorisation requests and to send others.
 * It can also issue access tokens.
 *
 * The "grant_type" "authorisation_code" and "pre-authorised_code" are supported
 * for authentication. The first one is always active. In order to facilitate the
 * building of the objects from this class, a builder has been developed.
 */
export declare class OpenIDReliyingParty {
    private defaultHolderMetadata;
    private metadata;
    private didResolver;
    private signCallback;
    private scopeVerificationFlag;
    private subjectComparison;
    private generalConfiguration;
    private issuerStateVerirication?;
    private authzDetailsVerification?;
    private vpCredentialVerificationCallback?;
    private preAuthCallback?;
    private nonceManager;
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
    constructor(defaultHolderMetadata: HolderMetadata, metadata: AuthServerMetadata, didResolver: Resolver, signCallback: RpTypes.TokenSignCallback, scopeVerificationFlag: boolean, stateManager: StateManager, subjectComparison: (firstId: string, secondId: string) => boolean, generalConfiguration: RpTypes.RpConfiguration, issuerStateVerirication?: ((state: string) => Promise<Result<null, Error>>) | undefined, authzDetailsVerification?: ((authDetails: AuthorizationDetails) => Promise<Result<null, Error>>) | undefined, vpCredentialVerificationCallback?: CredentialAdditionalVerification | undefined, preAuthCallback?: undefined | ((clientId: string | undefined, preCode: string, pin?: string) => Promise<Result<string, Error>>));
    /**
     * Allows to add support for a new DID Method
     * @param methodName DID Method name
     * @param resolver Object responsible for obtaining the DID Documents
     * related to the DID specified
     */
    addDidMethod(methodName: string, resolver: Resolvable): void;
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
    createIdTokenRequest(clientAuthorizationEndpoint: string, audience: string, redirectUri: string, requestPurpose: RpTypes.RequestPurpose, additionalParameters?: RpTypes.CreateTokenRequestOptionalParams): Promise<IdTokenRequest>;
    /**
     * Method that allows to build an VP Token Request directly, without
     * the need of a previous Base Authz Request
     * @param presentationDefinition The presentation definition to indicate to
     * the user
     * @param additionalParameters Additional parameters that handle
     * issues related to the content of the VP Token.
     * @returns A VP Token Request
     */
    directVpTokenRequestForVerification(presentationDefinition: RpTypes.PresentationDefinitionLocation, redirectUri: string, additionalParameters?: RpTypes.CreateTokenRequestOptionalParams): Promise<VpTokenRequest>;
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
    createVpTokenRequest(clientAuthorizationEndpoint: string, audience: string, redirectUri: string, presentationDefinition: RpTypes.PresentationDefinitionLocation, requestPurpose: RpTypes.RequestPurpose, additionalParameters?: RpTypes.CreateTokenRequestOptionalParams): Promise<VpTokenRequest>;
    private createNonceForPostBaseAuthz;
    /**
     * Allows to verify an authorisation request sent by a client
     * @param request The request sent by the client
     * @returns Verified Authz Reques with some of the client metadata extracted
     */
    verifyBaseAuthzRequest(request: AuthzRequestWithJWT): Promise<RpTypes.VerifiedBaseAuthzRequest>;
    private createNonceForPostAuthz;
    private checkNonceStateForPostBaseAuthz;
    /**
     * Allows to verify an ID Token Response sent by a client
     * @param idTokenResponse The authorisation response to verify
     * @returns The verified ID Token Response with the DID Document of the
     * associated token issuer.
     * @throws If data provided is incorrect
     */
    verifyIdTokenResponse(idTokenResponse: IdTokenResponse, checkTokenSignature?: boolean): Promise<RpTypes.VerifiedIdTokenResponse>;
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
    verifyVpTokenResponse(vpTokenResponse: VpTokenResponse, presentationDefinition: DIFPresentationDefinition, // TODO: Convert this to a callback
    vcSignatureVerification?: boolean): Promise<RpTypes.VerifiedVpTokenResponse>;
    private processNonceForPostAuthz;
    private generateCNonce;
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
    generateAccessToken(tokenRequest: TokenRequest, generateIdToken: boolean, audience: string, authServerPublicKeyJwk: JWK): Promise<TokenResponse>;
    private validateClientMetadata;
    private resolveClientMetadata;
}
export * from './types.js';
export * from './builder.js';
