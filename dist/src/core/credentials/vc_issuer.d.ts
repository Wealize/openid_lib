import { Resolver } from "did-resolver";
import { JWK } from "jose";
import { Jwt } from "jsonwebtoken";
import { W3CDataModel, W3CVerifiableCredentialFormats } from "../../common/formats/index.js";
import { CredentialRequest } from "../../common/interfaces/credential_request.interface.js";
import { IssuerMetadata } from "../../common/interfaces/issuer_metadata.interface.js";
import { CredentialResponse } from "../../common/interfaces/credential_response.interface.js";
import * as VcIssuerTypes from "./types.js";
import { CredentialDataManager } from './credential_data_manager.js';
import { NonceManager } from '../nonce/index.js';
/**
 * W3C credentials issuer in both deferred and In-Time flows
 */
export declare class W3CVcIssuer {
    private metadata;
    private didResolver;
    private issuerDid;
    private signCallback;
    private nonceManager;
    private credentialDataManager;
    /**
     * Constructor of the issuer
     * @param metadata Issuer metadata
     * @param didResolver Object that allows to resolve the DIDs found
     * @param issuerDid The DID of the issuer
     * @param signCallback Callback used to sign the VC generated
     * @param cNonceRetrieval Callback to recover the challenge nonce expected
     * for a control proof
     * @param getVcSchema Callback to recover the schema associated with a VC
     * @param getCredentialData Callback to recover the subject data to
     * include in the VC
     * It can also be used to specify if the user should follow the deferred flow
     */
    constructor(metadata: IssuerMetadata, didResolver: Resolver, issuerDid: string, signCallback: VcIssuerTypes.VcSignCallback, nonceManager: NonceManager, credentialDataManager: CredentialDataManager);
    /**
     * Allows to verify a JWT Access Token in string format
     * @param token The access token
     * @param publicKeyJwkAuthServer The public key that should verify the token
     * @param tokenVerifyCallback A callback that can be used to perform an
     * additional verification of the contents of the token
     * @returns Access token in JWT format
     * @throws If data provided is incorrect
     */
    verifyAccessToken(token: string, publicKeyJwkAuthServer: JWK, tokenVerifyCallback?: VcIssuerTypes.AccessTokenVerifyCallback): Promise<Jwt>;
    /**
     * Allows to generate a Credential Response in accordance to
     * the OID4VCI specification
     * @param acessToken The access token needed to perform the operation
     * @param credentialRequest The credential request sent by an user
     * @param dataModel The W3 VC Data Model version
     * @returns A credential response with a VC or a deferred code
     * @throws If data provided is incorrect
     */
    generateCredentialResponse(acessToken: Jwt, credentialRequest: CredentialRequest, dataModel: W3CDataModel): Promise<CredentialResponse>;
    private credentialResponseMatch;
    /**
     * Allows for the generation of a VC without an Access Token
     * @param did The DID if the holder of the VC
     * @param dataModel The W3 VC Data Model version
     * @param types The types of the VCs
     * @param format The format of the VC
     * @returns A credential response with the VC
     */
    generateVcDirectMode(did: string, dataModel: W3CDataModel, types: string[], format: W3CVerifiableCredentialFormats): Promise<CredentialResponse>;
    private generateCredentialTimeStamps;
    private generateVcId;
    private generateW3CDataForV1;
    private generateW3CDataForV2;
    private generateW3CCredential;
    /**
     * Allows to exchange a deferred code for a VC
     * @param acceptanceToken The deferred code sent by the issuer in a
     * previous instance
     * @param dataModel The W3C VC Data Model version
     * @returns A credential response with the VC generated or a new
     * (or the same) deferred code
     */
    exchangeAcceptanceTokenForVc(acceptanceToken: string, dataModel: W3CDataModel): Promise<CredentialResponse>;
    private checkCredentialTypesAndFormat;
}
