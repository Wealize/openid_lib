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