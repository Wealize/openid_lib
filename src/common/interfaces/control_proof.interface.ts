import { ControlProofType } from "../types/index.js";

export interface BaseControlProof {
  proof_type: ControlProofType;
  [key: string]: any
}
