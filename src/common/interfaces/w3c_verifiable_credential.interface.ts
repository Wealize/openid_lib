// Based on VCDM 2.0
// TODO: Think if support for VCDM 1.0 should be given
export interface W3CVerifiableCredential {
  '@context': string[];
  type: string[];
  credentialSchema?: W3CVcSchemaDefinition[];
  issuer: string;
  validFrom?: string; // Date timestamp. Example: "2010-01-01T19:23:24Z",
  validUntil?: string; // Date timestamp. Example: "2010-01-01T19:23:24Z",
  id?: string;
  credentialStatus?: W3CCredentialStatus;
  description?: string;
  credentialSubject: W3CSingleCredentialSubject;
  proof?: EmbeddedProof;
  [x: string]: any
}

export interface W3CVcSchemaDefinition {
  id: string;
  type: string;
}

export interface W3CCredentialStatus {
  id?: string;
  type: string;
  [key: string]: any
}

export interface W3CSingleCredentialSubject {
  id?: string;
  [key: string]: any
}

// Documentation: https://www.w3.org/TR/vc-data-integrity/#proofs
export interface EmbeddedProof {
  id?: string;
  type: string;
  proofPurpose: string;
  verificationMethod: string;
  created?: string; // Date timestamp. Example: "2010-01-01T19:23:24Z",
  expires?: string; // Date timestamp. Example: "2010-01-01T19:23:24Z",
  domain?: string;
  challenge?: string;
  proofValue: string;
  previousProof?: string | string[];
  nonce?: string;
}
