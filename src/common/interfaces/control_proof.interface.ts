import { ControlProofType } from "common/types";

export interface BaseControlProof {
  proof_type: ControlProofType;
  [key: string]: any
}
