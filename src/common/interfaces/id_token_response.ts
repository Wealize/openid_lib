import { JwtPayload } from "jsonwebtoken";

export interface IdTokenResponse {
  id_token: string;
  [key: string]: any;
}

export interface IdTokenResponsePayload extends JwtPayload {
  state?: string;
  nonce: string;
}
