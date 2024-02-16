import { W3CVerifiableCredentialFormats } from "../formats/index.js";
import { BaseControlProof } from "./control_proof.interface.js";

export interface CredentialRequest {
  types: string[];
  format: W3CVerifiableCredentialFormats;
  proof: BaseControlProof
}
