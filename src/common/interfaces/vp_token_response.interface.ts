import { JwtPayload } from "jsonwebtoken";
import { W3CVerifiablePresentation } from "./verifiable_presentation.interface";

export interface JwtVpPayload extends JwtPayload {
  vp: W3CVerifiablePresentation;
}
