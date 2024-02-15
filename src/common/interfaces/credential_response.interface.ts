import { W3CVerifiableCredentialFormats } from "common/formats";
import { W3CVerifiableCredential } from "./w3c_verifiable_credential.interface";
import { CompactVc } from "common/types";

export interface CredentialResponse {
  format?: W3CVerifiableCredentialFormats;
  credential?: W3CVerifiableCredential | CompactVc;
  acceptance_token?: string;
  c_nonce?: string;
  c_nonce_expires_in?: number // Seconds
}
