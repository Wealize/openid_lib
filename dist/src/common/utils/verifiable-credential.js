import jsonpath from "jsonpath";
export function extractFromCredential(vc, path) {
    const pathResult = jsonpath.query(vc, path, 1);
    if (pathResult.length) {
        return pathResult[0];
    }
    return undefined;
}
