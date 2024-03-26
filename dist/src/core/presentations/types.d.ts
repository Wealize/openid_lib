import { KeyLike } from "jose";
import { W3CDataModel } from "../../common/formats/index.js";
import { W3CVerifiableCredential } from "../../common/interfaces/index.js";
import { VerificationResult } from "../../common/types/index.js";
export type CredentialAdditionalVerification = (vc: W3CVerifiableCredential, dmVersion: W3CDataModel, issuerPublickKey?: KeyLike | Uint8Array) => Promise<VerificationResult>;
export type NonceVerification = (subject: string, nonce: string) => Promise<VerificationResult>;
export type VpExtractedData = {
    claimsData: Record<string, any>;
    holderDid: string;
};
