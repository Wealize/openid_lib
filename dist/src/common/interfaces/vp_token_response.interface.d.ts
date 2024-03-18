import { JwtPayload } from "jsonwebtoken";
import { W3CVerifiablePresentation } from "./verifiable_presentation.interface";
import { DIFPresentationSubmission } from "./presentation_submission.interface";
/**
 * Defines an authorization response for the response type "vp_token"
 */
export interface VpTokenResponse {
    vp_token: string;
    presentation_submission: DIFPresentationSubmission;
    [key: string]: any;
}
export interface JwtVpPayload extends JwtPayload {
    vp: W3CVerifiablePresentation;
}
