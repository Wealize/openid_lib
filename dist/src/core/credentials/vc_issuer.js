var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { v4 as uuidv4 } from 'uuid';
import { P, match } from 'ts-pattern';
import moment from 'moment';
import { ControlProof } from "../../common/classes/control_proof.js";
import { CONTEXT_VC_DATA_MODEL_1, CONTEXT_VC_DATA_MODEL_2, C_NONCE_EXPIRATION_TIME } from "../../common/constants/index.js";
import { W3CDataModel } from "../../common/formats/index.js";
import { decodeToken, verifyJwtWithExpAndAudience } from "../../common/utils/jwt.utils.js";
import { VcFormatter } from './formatters.js';
import { InternalNonceError, InvalidCredentialRequest, InvalidDataProvided, InvalidProof, InvalidToken } from "../../common/classes/index.js";
import { areDidUrlsSameDid } from '../../common/utils/did.utils.js';
import { arraysAreEqual } from '../../common/utils/array.utils.js';
import { NonceManager } from '../nonce/index.js';
/**
 * W3C credentials issuer in both deferred and In-Time flows
 */
export class W3CVcIssuer {
    constructor(metadata, didResolver, issuerDid, signCallback, stateManager, credentialDataManager, vcTypesContextRelationship) {
        this.metadata = metadata;
        this.didResolver = didResolver;
        this.issuerDid = issuerDid;
        this.signCallback = signCallback;
        this.credentialDataManager = credentialDataManager;
        this.vcTypesContextRelationship = vcTypesContextRelationship;
        this.nonceManager = new NonceManager(stateManager);
    }
    /**
     * Allows to verify a JWT Access Token in string format
     * @param token The access token
     * @param publicKeyJwkAuthServer The public key that should verify the token
     * @param tokenVerifyCallback A callback that can be used to perform an
     * additional verification of the contents of the token
     * @returns Access token in JWT format
     * @throws If data provided is incorrect
     */
    verifyAccessToken(token, publicKeyJwkAuthServer, tokenVerifyCallback) {
        return __awaiter(this, void 0, void 0, function* () {
            yield verifyJwtWithExpAndAudience(token, publicKeyJwkAuthServer, this.metadata.credential_issuer);
            const jwt = decodeToken(token);
            if (tokenVerifyCallback) {
                const verificationResult = yield tokenVerifyCallback(jwt.header, jwt.payload);
                if (!verificationResult.valid) {
                    throw new InvalidToken(`Invalid access token provided${verificationResult.error ? ": " + verificationResult.error : '.'}`);
                }
            }
            return jwt;
        });
    }
    /**
     * Allows to generate a Credential Response in accordance to
     * the OID4VCI specification
     * @param acessToken The access token needed to perform the operation
     * @param credentialRequest The credential request sent by an user
     * @param dataModel The W3 VC Data Model version
     * @returns A credential response with a VC or a deferred code
     * @throws If data provided is incorrect
     */
    generateCredentialResponse(acessToken, credentialRequest, dataModel) {
        return __awaiter(this, void 0, void 0, function* () {
            this.checkCredentialTypesAndFormat(credentialRequest.types, credentialRequest.format);
            const controlProof = ControlProof.fromJSON(credentialRequest.proof);
            const proofAssociatedClient = controlProof.getAssociatedIdentifier();
            const jwtPayload = acessToken.payload;
            const innerNonce = jwtPayload.nonce;
            const cNonceResult = yield this.nonceManager.getChallengeNonce(innerNonce);
            if (cNonceResult.isError()) {
                throw new InvalidProof("Invalid provided nonce for control proof");
            }
            const cNonce = cNonceResult.unwrap();
            if (cNonce.timestamp + cNonce.expirationTime <= Date.now()) {
                this.nonceManager.deleteNonce(innerNonce);
                throw new InvalidCredentialRequest("Challenge nonce has expired");
            }
            match(cNonce)
                .with({ operationType: { type: "Verification" } }, (_) => {
                    throw new InvalidCredentialRequest("Invalid provided nonce");
                })
                .with({ operationType: { type: "Issuance", vcTypes: { type: "Know", vcTypes: P.select() } } }, (types) => {
                    if (!areDidUrlsSameDid(proofAssociatedClient, jwtPayload.sub)) {
                        throw new InvalidToken("Access Token was issued for a different identifier that the one that sign the proof");
                    }
                    if (!arraysAreEqual(types, credentialRequest.types)) {
                        throw new InvalidCredentialRequest("The provided token does not allow for the issuance of a VC of the specified types");
                    }
                })
                .with({ operationType: { type: "Issuance", vcTypes: { type: "Uknown" } } }, (_) => {
                    // Most probably generated from pre-auth flow
                })
                .otherwise(() => {
                    throw new InternalNonceError("Unexpected behaviour detected at nonce matching");
                });
            yield controlProof.verifyProof(innerNonce, this.metadata.credential_issuer, this.didResolver);
            const credentialSubject = yield this.credentialDataManager.resolveCredentialSubject(jwtPayload.sub, proofAssociatedClient);
            const credentialResponse = yield this.credentialResponseMatch(credentialRequest.types, credentialSubject, credentialRequest.format, dataModel);
            this.nonceManager.deleteNonce(innerNonce);
            return credentialResponse;
        });
    }
    credentialResponseMatch(types, credentialSubject, format, dataModel) {
        return __awaiter(this, void 0, void 0, function* () {
            const credentialDataOrDeferred = yield this.credentialDataManager.getCredentialData(types, credentialSubject);
            return match(credentialDataOrDeferred)
                .with({ type: "InTime" }, (data) => __awaiter(this, void 0, void 0, function* () {
                    return this.generateW3CCredential(types, data.schema, credentialSubject, data, format, dataModel);
                }))
                .with({ type: "Deferred" }, (data) => {
                    return {
                        acceptance_token: data.deferredCode
                    };
                })
                .exhaustive();
        });
    }
    /**
     * Allows for the generation of a VC without an Access Token
     * @param did The DID if the holder of the VC
     * @param dataModel The W3 VC Data Model version
     * @param types The types of the VCs
     * @param format The format of the VC
     * @returns A credential response with the VC
     */
    generateVcDirectMode(did, dataModel, types, format) {
        return __awaiter(this, void 0, void 0, function* () {
            this.checkCredentialTypesAndFormat(types, format);
            return yield this.credentialResponseMatch(types, did, format, dataModel);
        });
    }
    // TODO: valorar quitar iss de 'CredentialDataOrDeferred' y homogeneizar comportamiento entre V1 y V2
    // El motivo es que V1 incluye un campo issuanceDate, y además EBSI está obligando a que sea igual al 'iat' del token.
    // Sin embargo, en V2 ese campo no existe. La propusta sería:
    // - En V2, validFrom se asocia con nbf, y iat sería Date.now(). Según esto, en formatDataModel2, iat debería ajustarse a
    //   Date.now() y valorar quitar el nbf o también asignarlo a Date.now(). Notar diferencia entre info de la credencial y del token
    // - En V1, validFrom se asocia con nbf, issued y issuanceDate y iat con Date.now()
    generateCredentialTimeStamps(data) {
        if (data.validUntil && data.expiresInSeconds) {
            throw new InvalidDataProvided(`"expiresInSeconds" and "validUntil" can't be defined at the same time`);
        }
        const issuanceDate = (() => {
            const iss = data.iss ? moment(data.iss, true) : moment();
            if (!iss.isValid()) {
                throw new InvalidDataProvided(`Invalid specified date for "iss" parameter`);
            }
            return iss;
        })();
        const validFrom = (() => {
            const nbf = data.nbf ? moment(data.nbf, true) : issuanceDate.clone();
            if (!nbf.isValid()) {
                throw new InvalidDataProvided(`Invalid specified date for "nbf" parameter`);
            }
            if (nbf.isBefore(issuanceDate)) {
                throw new InvalidDataProvided(`"validFrom" can not be before "issuanceDate"`);
            }
            return nbf;
        })();
        const expirationDate = (() => {
            const exp = (() => {
                if (data.validUntil) {
                    return moment(data.validUntil, true);
                }
                else if (data.expiresInSeconds) {
                    return issuanceDate.clone().add(data.expiresInSeconds, 'seconds');
                }
                else {
                    return undefined;
                }
            })();
            if (exp) {
                if (!exp.isValid()) {
                    throw new InvalidDataProvided(`Invalid specified date for "expirationDate" parameter`);
                }
                if (exp.isBefore(validFrom)) {
                    throw new InvalidDataProvided(`"expirationDate" can not be before "validFrom"`);
                }
            }
            return exp;
        })();
        return {
            issuanceDate: issuanceDate.utc().toISOString(),
            validFrom: validFrom.utc().toISOString(),
            expirationDate: expirationDate ? expirationDate.utc().toISOString() : undefined,
        };
    }
    generateVcId() {
        return `urn:uuid:${uuidv4()}`;
    }
    generateW3CDataForV1(type, schema, subject, vcData) {
        const timestamps = this.generateCredentialTimeStamps(vcData.metadata);
        const vcId = this.generateVcId();
        return {
            "@context": CONTEXT_VC_DATA_MODEL_1,
            type,
            credentialSchema: schema,
            issuanceDate: timestamps.issuanceDate,
            validFrom: timestamps.validFrom,
            expirationDate: timestamps.expirationDate,
            id: vcId,
            credentialStatus: vcData.status,
            issuer: this.issuerDid,
            issued: timestamps.issuanceDate,
            termsOfUse: vcData.termfOfUse,
            credentialSubject: Object.assign({ id: subject }, vcData.data)
        };
    }
    generateW3CDataForV2(type, schema, subject, vcData) {
        const vcId = this.generateVcId();
        const timestamps = this.generateCredentialTimeStamps(vcData.metadata);
        return {
            "@context": CONTEXT_VC_DATA_MODEL_2,
            type,
            credentialSchema: schema,
            validFrom: timestamps.validFrom,
            validUntil: timestamps.expirationDate,
            id: vcId,
            credentialStatus: vcData.status,
            termsOfUse: vcData.termfOfUse,
            issuer: this.issuerDid,
            credentialSubject: Object.assign({ id: subject }, vcData.data)
        };
    }
    extendsVcContext(content) {
        if (!this.vcTypesContextRelationship) {
            return;
        }
        const typesToExtend = Object.keys(this.vcTypesContextRelationship);
        for (const type of content.type) {
            if (typesToExtend.includes(type)) {
                content['@context'].push(this.vcTypesContextRelationship[type]);
            }
        }
    }
    generateW3CCredential(type, schema, subject, vcData, format, dataModel) {
        return __awaiter(this, void 0, void 0, function* () {
            const formatter = VcFormatter.fromVcFormat(format, dataModel);
            const content = dataModel === W3CDataModel.V1 ?
                this.generateW3CDataForV1(type, schema, subject, vcData) :
                this.generateW3CDataForV2(type, schema, subject, vcData);
            this.extendsVcContext(content);
            const vcPreSign = formatter.formatVc(content);
            const signedVc = yield this.signCallback(format, vcPreSign);
            // Generate a new nonce
            const nonce = uuidv4();
            const expirationTime = C_NONCE_EXPIRATION_TIME; // TODO: Make it configurable
            this.nonceManager.saveNonce(nonce, {
                timestamp: Date.now(),
                sub: subject,
                operationType: {
                    type: 'Issuance',
                    vcTypes: {
                        type: "Know",
                        vcTypes: type,
                    }
                },
                type: 'ChallengeNonce',
                expirationTime
            });
            return {
                format: format,
                credential: signedVc,
                c_nonce: nonce,
                c_nonce_expires_in: expirationTime // TODO: This could be interesting to be configurable
            };
        });
    }
    /**
     * Allows to exchange a deferred code for a VC
     * @param acceptanceToken The deferred code sent by the issuer in a
     * previous instance
     * @param dataModel The W3C VC Data Model version
     * @returns A credential response with the VC generated or a new
     * (or the same) deferred code
     */
    exchangeAcceptanceTokenForVc(acceptanceToken, dataModel) {
        return __awaiter(this, void 0, void 0, function* () {
            const exchangeResult = yield this.credentialDataManager.deferredExchange(acceptanceToken);
            if (exchangeResult.isError()) {
                throw new InvalidToken(`Invalid acceptance token: ${exchangeResult.unwrapError().message}`);
            }
            const credentialDataResponse = exchangeResult.unwrap();
            return yield match(credentialDataResponse)
                .with({ type: "InTime" }, (dataResponse) => __awaiter(this, void 0, void 0, function* () {
                    return this.generateW3CCredential(dataResponse.types, dataResponse.schema, dataResponse.data.id, dataResponse, dataResponse.format, dataModel);
                }))
                .with({ type: "Deferred" }, (data) => {
                    return {
                        acceptance_token: data.deferredCode
                    };
                })
                .exhaustive();
        });
    }
    checkCredentialTypesAndFormat(types, format) {
        const typesSet = new Set(types);
        for (const credentialSupported of this.metadata.credentials_supported) {
            const supportedSet = new Set(credentialSupported.types);
            if ([...typesSet].every((item) => supportedSet.has(item)) && credentialSupported.format === format) {
                return;
            }
        }
        throw new InvalidCredentialRequest("Unsuported combination of credential types and format");
    }
}
