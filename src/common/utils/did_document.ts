import { DIDDocument } from "did-resolver";
import { JWK } from "jose";

export function getAuthentificationJWKKeys(
  didDocument: DIDDocument,
  methodIdentifier: string,
): JWK {
  if (!didDocument.authentication?.includes(methodIdentifier)) {
    throw new Error("The kid speciifed is not specified as a authentification relationship");
  }
  if (!didDocument.verificationMethod) {
    throw new Error(`No verification methods defined in DidDocumet for did ${didDocument.id}`);
  }
  const verificationMethod = didDocument.verificationMethod.find((method) => method.id === methodIdentifier);
  if (!verificationMethod) {
    throw new Error(`There is no verification method with id ${methodIdentifier}`);
  }
  if (!verificationMethod.publicKeyJwk) {
    throw new Error("The verificationMethod must contain public key with JWK format");
  }
  return verificationMethod.publicKeyJwk;
}
