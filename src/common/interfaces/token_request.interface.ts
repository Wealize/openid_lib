import { GrantType } from "common/types";

export interface TokenRequest {
  grant_type: GrantType;
  client_id: string;
  code?: string;
  code_verifier?: string;
  "pre-authorised_code"?: string;
  user_pin?: string;
  vp_token?: string;
}
