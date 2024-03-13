import jsonpath from "jsonpath";
import { W3CVerifiableCredential } from "../interfaces";

export function extractFromCredential(
  vc: W3CVerifiableCredential,
  path: string
) {
  const pathResult = jsonpath.query(vc, path, 1);
  if (pathResult.length) {
    return pathResult[0];
  }
  return undefined;
}
