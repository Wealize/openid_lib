import { JWK, importJWK, jwtVerify } from "jose";
import * as jwt from "jsonwebtoken";

export function decodeToken(
  jsonWebtoken: string,
): jwt.Jwt {
  const result = jwt.decode(jsonWebtoken, { complete: true });
  if (!result) {
    throw new Error("Invalid JWT for decoding");

  }
  return result;
}

export async function verifyJwtWithExpAndAudience(
  token: string,
  publicKeyJWK: JWK,
  audience?: string
) {
  const { payload } = decodeToken(token);
  const jwtPayload = payload as jwt.JwtPayload;
  if (!jwtPayload.exp || jwtPayload.exp < Date.now()) {
    throw new Error("JWT is expired or does not have exp parameter");
  }
  if (audience) {
    if (!jwtPayload.aud || jwtPayload.aud !== audience) {
      throw new Error("JWT audience is invalid or is not defined");
    }
  }
  const publicKey = await importJWK(publicKeyJWK);
  await jwtVerify(token, publicKey);
}

export function obtainDid(kid: string, iss?: string): string {
  if (iss && iss.startsWith("did")) {
    return iss;
  }
  if (!kid.startsWith("did")) {
    throw new Error(`Can't extract did from "kid" parameter`);
  }
  return kid.trim().split("#")[0]
}