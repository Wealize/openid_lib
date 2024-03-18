import { DIFPresentationDefinition } from "../../common/interfaces/presentation_definition.interface";
import { DIFPresentationSubmission } from "../../common/interfaces/presentation_submission.interface";
import { Resolver } from "did-resolver";
import { CredentialAdditionalVerification, NonceVerification } from "./types";
export declare class VpResolver {
    private didResolver;
    private audience;
    private externalValidation;
    private nonceValidation;
    private jwtCache;
    private vpHolder;
    constructor(didResolver: Resolver, audience: string, externalValidation: CredentialAdditionalVerification, nonceValidation: NonceVerification);
    verifyPresentation(vp: any, definition: DIFPresentationDefinition, submission: DIFPresentationSubmission): Promise<Record<string, any>>;
    private deserializeJwtVc;
    private getSchema;
    private decodeAndParse;
    private deserializeJwtVp;
    private checkDateValidities;
    private checkVcDataModel;
    private checkFormatValidity;
    private extractCredentialFromVp;
    private resolveJsonPath;
    private resolveInputDescriptor;
    private findDefinitionInputDescriptor;
}
