import { W3CVerifiableCredentialFormats } from "common/formats";
import { BaseControlProof } from "./control_proof.interface";

export interface CredentialRequest {
  types: string[];
  format: W3CVerifiableCredentialFormats;
  proof: BaseControlProof
}
