export interface TokenResponse {
  access_token: string;
  id_token?: string;
  token_type: "bearer";
  expires_in: number; // Seconds
  c_nonce: string;
  c_nonce_expires_in: number // Seconds
}
