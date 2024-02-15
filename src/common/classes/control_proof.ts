import { JWA_ALGS } from "common/constants";
import { ControlProofType } from "common/types";
import { getAuthentificationJWKKeys } from "common/utils/did_document";
import { decodeToken, obtainDid } from "common/utils/jwt.utils";
import { Resolvable } from "did-resolver";
import { importJWK, jwtVerify } from "jose";
import { JwtPayload } from "jsonwebtoken";
import { InvalidProof } from "./error";

export abstract class ControlProof {
  format: ControlProofType;

  protected constructor(format: ControlProofType) {
    this.format = format;
  }

  abstract getAssociatedIdentifier(): string;
  abstract toJSON(): Record<string, string>;

  abstract verifyProof(
    cNonce: string,
    audience: string,
    didResolver: Resolvable
  ): Promise<void>;

  static fromJSON(data: Record<string, any>): ControlProof {
    if (!data.format) {
      throw new InvalidProof(`The "format" parameter is required in a control proof`);
    }
    if (data.format === "jwt") {
      if (!data.jwt) {
        throw new InvalidProof(`Proof of format "jwt" needs a "jwt" paramater`);
      }
      return ControlProof.jwtProof(data.jwt);
    } else {
      throw new InvalidProof("Invalid format specified");
    }
  }

  static jwtProof(jwt: string): JwtControlProof {
    return new JwtControlProof("jwt", jwt);
  }
}

class JwtControlProof extends ControlProof {
  private clientIdentifier?: string;

  constructor(format: ControlProofType, private jwt: string) {
    super(format);
  }

  toJSON(): Record<string, string> {
    return {
      format: this.format,
      jwt: this.jwt
    }
  }

  getAssociatedIdentifier(): string {
    if (!this.clientIdentifier) {
      const { header, payload } = decodeToken(this.jwt);
      if (!header.kid) {
        throw new InvalidProof(`"kid" parameter must be specified`);
      }
      this.clientIdentifier = obtainDid(header.kid, (payload as JwtPayload).iss);
    }
    return this.clientIdentifier;
  }

  async verifyProof(
    cNonce: string,
    audience: string,
    didResolver: Resolvable
  ): Promise<void> {
    const { header, payload } = decodeToken(this.jwt);
    const jwtPayload = payload as JwtPayload;
    if (!header.typ || header.typ !== "penid4vci-proof+jwt") {
      throw new InvalidProof(`Invalid "typ" paramater in proof header`);
    }
    if (header.alg as JWA_ALGS === "none") {
      throw new InvalidProof(`The value of "alg" parameter can't be none`);
    }
    if (!header.kid) {
      throw new InvalidProof(`"kid" parameter must be specified`);
    }
    if (!jwtPayload.aud || jwtPayload.aud !== audience) {
      throw new InvalidProof(`"aud" parameter is not specified or is invalid`);
    }
    if (!jwtPayload.iat) {
      throw new InvalidProof(`"iat" parameter must be specified`);
    }
    if (!jwtPayload.nonce || jwtPayload.nonce !== cNonce) {
      throw new InvalidProof(`"nonce" parameter is not specified or is invalid`);
    }
    const did = this.clientIdentifier ?? obtainDid(header.kid, jwtPayload.iss);
    const didResolution = await didResolver.resolve(did);
    if (didResolution.didResolutionMetadata.error) {
      throw new InvalidProof(`Did resolution failed. Error ${didResolution.didResolutionMetadata.error
        }: ${didResolution.didResolutionMetadata.message}`);
    }
    const didDocument = didResolution.didDocument!;
    let publicKeyJwk;
    try {
      publicKeyJwk = getAuthentificationJWKKeys(didDocument, header.kid);
    } catch (error: any) {
      throw new InvalidProof(error.message);
    }
    const publicKey = await importJWK(publicKeyJwk);
    await jwtVerify(this.jwt, publicKey);
  }

}
