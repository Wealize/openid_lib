import { JWA_ALGS } from "../constants";
import { W3CVerifiableCredentialFormats, W3CVerifiablePresentationFormats } from "../formats";
export interface DIFPresentationDefinition {
    id: string;
    input_descriptors: PresentationInputDescriptor[];
    name?: string;
    purpose?: string;
    format: LdFormat & JwtFormat;
}
export interface PresentationInputDescriptor {
    id: string;
    name?: string;
    purpose?: string;
    format?: LdFormat & JwtFormat;
    constraints: InputDescriptorContraintType;
}
export interface InputDescriptorFielType {
    path: string[];
    id?: string;
    purpose?: string;
    name?: string;
    filter?: Record<string, unknown>;
    optional?: boolean;
}
export interface InputDescriptorContraintType {
    fields?: InputDescriptorFielType[];
    limit_disclosure?: 'required' | 'preferred';
}
export type LdFormat = {
    [key in keyof Pick<W3CVerifiableCredentialFormats & W3CVerifiablePresentationFormats, "jwt_vc_json-ld" | "ldp_vc" | "ldp_vp">]?: {
        proof_type: Exclude<JWA_ALGS, "none">[];
    };
};
export type JwtFormat = {
    [key in keyof Pick<W3CVerifiableCredentialFormats & W3CVerifiablePresentationFormats, "jwt_vc_json" | "jwt_vc" | "jwt_vp_json" | "jwt_vp">]?: {
        alg: Exclude<JWA_ALGS, "none">[];
    };
};
