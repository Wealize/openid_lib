import { W3CVerifiableCredentialFormats } from "../formats/index.js";
import { W3CVerifiableCredential } from "./w3c_verifiable_credential.interface.js";
import { CompactVc } from "../types/index.js";

export interface CredentialResponse {
  format?: W3CVerifiableCredentialFormats;
  credential?: W3CVerifiableCredential | CompactVc;
  acceptance_token?: string;
  c_nonce?: string;
  c_nonce_expires_in?: number // Seconds
}
