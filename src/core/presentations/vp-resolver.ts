import jsonpath from "jsonpath";
import {
  DIFPresentationDefinition, JwtFormat, LdFormat, PresentationInputDescriptor
} from "../../common/interfaces/presentation_definition.interface";
import {
  DIFPresentationSubmission,
  DescriptorMap
} from "../../common/interfaces/presentation_submission.interface";
import {
  W3CVerifiablePresentation
} from "../../common/interfaces/verifiable_presentation.interface";
import {
  W3CDataModel,
  W3CVerifiableCredentialFormats,
  W3CVerifiablePresentationFormats
} from "../../common/formats";
import {
  CONTEXT_VC_DATA_MODEL_1,
  CONTEXT_VC_DATA_MODEL_2,
  JWA_ALGS,
  JwtVpPayload,
  VcJwtPayload,
  W3CVerifiableCredential,
  W3CVerifiableCredentialV1,
  W3CVerifiableCredentialV2,
  W3C_VP_TYPE,
  decodeToken,
  getAssertionMethodJWKKeys,
  getAuthentificationJWKKeys,
  obtainDid
} from "../../common";
import { JwtPayload } from "jsonwebtoken";
import { Resolver } from "did-resolver";
import { importJWK, jwtVerify } from "jose";

export class VpResolver {
  // TODO: Implement cache-like structure just in case a single VC is able to satisfy various
  constructor(private didResolver: Resolver) {

  }

  private async deserializeJwtVc(
    data: any,
    validAlgs: JWA_ALGS[]
  ): Promise<{
    data: VcJwtPayload,
    jwa: JWA_ALGS
  }> {
    if (typeof data !== "string") {
      // TODO: Define Error type
      throw new Error("INVALID FORMAT");
    }
    const { header, payload } = decodeToken(data);
    if (!header.kid) {
      // TODO: Define error type
      throw new Error("Must contain a kid parameter");
    }
    if (!validAlgs.includes(header.alg as JWA_ALGS)) {
      throw new Error(`Unssuported JWA: ${header.alg}`);
    }
    if (!("vc" in (payload as JwtPayload))) {
      throw new Error("Object is not a JWT VC");
    }
    const vc = (payload as VcJwtPayload).vc as W3CVerifiableCredential;
    const dataModelVersion = this.checkVcDataModel(vc);
    this.checkDateValidities(vc, dataModelVersion);
    const didResolution = await this.didResolver.resolve(vc.issuer);
    if (didResolution.didResolutionMetadata.error) {
      // TODO: Define new error type
      throw new Error(`Did resolution failed. Error ${didResolution.didResolutionMetadata.error
        }: ${didResolution.didResolutionMetadata.message}`);
    }
    const didDocument = didResolution.didDocument!;
    const jwk = getAssertionMethodJWKKeys(didDocument, header.kid);
    const publicKey = await importJWK(jwk);
    // TODO: MOST PROBABLY WE SHOULD CATCH THE POSSIBLE EXCEPTION THAT THIS METHOD MAY THROW
    await jwtVerify(data, publicKey);
    return {
      data: payload as VcJwtPayload,
      jwa: header.alg as JWA_ALGS
    }
  }

  private async decodeAndParse(
    format: W3CVerifiableCredentialFormats | W3CVerifiablePresentationFormats,
    data: any,
    validAlgs: JWA_ALGS[]
  ): Promise<{
    data: JwtVpPayload | VcJwtPayload,
    jwa: JWA_ALGS
  }> {
    if (checkIfLdFormat(format)) {
      // TODO: Change error type
      throw new Error("LD Format are not supported right now");
    }
    let tmp;
    switch (format) {
      case "jwt_vc":
      case "jwt_vc_json":
        return { ...await this.deserializeJwtVc(data, validAlgs) };
      case "jwt_vp":
      case "jwt_vp_json":
        return { ...await this.deserializeJwtVp(data, validAlgs) };
      case "jwt_vc_json-ld":
      case "ldp_vc":
      case "ldp_vp":
        throw new Error("LD formats are not supported right now");
    }
  }

  private async deserializeJwtVp(
    data: any,
    validAlgs: JWA_ALGS[]
  ): Promise<{
    data: JwtVpPayload,
    jwa: JWA_ALGS
  }> {
    // TODO: It could be interesting to chech against a json schema or with joi
    if (typeof data !== "string") {
      // TODO: Define Error type
      throw new Error("INVALID FORMAT");
    }
    const { header, payload } = decodeToken(data);
    if (!header.kid) {
      // TODO: Define error type
      throw new Error("Must contain a kid parameter");
    }
    if (!validAlgs.includes(header.alg as JWA_ALGS)) {
      throw new Error(`Unssuported JWA: ${header.alg}`);
    }
    if (!("vp" in (payload as JwtPayload))) {
      throw new Error("Object is not a JWT VP");
    }
    const vp = (payload as JwtVpPayload).vp as W3CVerifiablePresentation;
    // TODO: WE SHOULD CHECK THE DATA MOVEL VERSION. SHOULD IT BE THE SAME AS THE VC?
    if (!vp.type.includes(W3C_VP_TYPE)) {
      // TODO: Define error type
      throw new Error("Invalid Type specification for VP");
    }
    // TODO: CATCH POSSIBLE EXCEPTION
    const holderDid = obtainDid(header.kid, vp.holder);
    const didResolution = await this.didResolver.resolve(holderDid);
    if (didResolution.didResolutionMetadata.error) {
      // TODO: Define new error type
      throw new Error(`Did resolution failed. Error ${didResolution.didResolutionMetadata.error
        }: ${didResolution.didResolutionMetadata.message}`);
    }
    const didDocument = didResolution.didDocument!;
    const jwk = getAuthentificationJWKKeys(didDocument, header.kid);
    const publicKey = await importJWK(jwk);
    // TODO: MOST PROBABLY WE SHOULD CATCH THE POSSIBLE EXCEPTION THAT THIS METHOD MAY THROW
    await jwtVerify(data, publicKey);
    return {
      data: payload as JwtVpPayload,
      jwa: header.alg as JWA_ALGS
    }
  }

  private checkDateValidities(
    vc: W3CVerifiableCredential,
    dataModel: W3CDataModel
  ) {
    const now = Date.now();
    switch (dataModel) {
      case W3CDataModel.V1:
        const vcV1 = vc as W3CVerifiableCredentialV1;
        if (!vcV1.issuanceDate) {
          // TODO: Define error type
          throw new Error("A W3CVCDMV1 Must containd a issuanceDate parameter");
        }
        const issuanceDate = Date.parse(vcV1.issuanceDate);
        if (now < issuanceDate) {
          // TODO: Define error type
          throw new Error("Invalid issuance date");
        }
        if (vcV1.expirationDate) {
          const expirationDate = Date.parse(vcV1.expirationDate);
          if (now >= expirationDate) {
            // TODO: Define error type
            throw new Error("THE VC HAS EXPIRED");
          }
        }
        break
      case W3CDataModel.V2:
        const vcV2 = vc as W3CVerifiableCredentialV2;
        if (vcV2.validFrom) {
          const validFrom = Date.parse(vcV2.validFrom);
          if (validFrom > now) {
            // TODO: Define error type
            throw new Error("The VC is not yet valid");
          }
        }
        if (vcV2.validUntil) {
          const validUntil = Date.parse(vcV2.validUntil);
          if (validUntil <= now) {
            // TODO: Define error type
            throw new Error("THE VC HAS EXPIRED");
          }
        }
        break
    }
  }

  private checkVcDataModel(
    vc: W3CVerifiableCredential
  ): W3CDataModel {
    if (CONTEXT_VC_DATA_MODEL_1.every((x) => vc["@context"].includes(x))) {
      return W3CDataModel.V1;
    }
    if (CONTEXT_VC_DATA_MODEL_2.every((x) => vc["@context"].includes(x))) {
      return W3CDataModel.V2;
    }
    // TODO: Define error type
    throw new Error("INVALID DATA MODEL")
  }

  private generateInputDescriptorMap(
    definition: DIFPresentationDefinition
  ) {

  }

  private checkFormatValidity(
    expectedFormats: LdFormat & JwtFormat,
    currentFormat: W3CVerifiableCredentialFormats | W3CVerifiablePresentationFormats
  ): JWA_ALGS[] {
    const formatData = expectedFormats[currentFormat];
    if (!formatData) {
      // TODO: Define error type
      throw new Error("Unexpected format detected / Format not supported");
    }
    if (("proof_type") in formatData) {
      // TODO: NOT SUPPORTED FOR NOW
      throw new Error("JLD not supported right now");
    }
    if (("alg") in formatData) {
      return formatData.alg;
    }
    // TODO: Define error type
    throw new Error("Invalid format data");
  }

  private async extractCredentialFromVp(
    data: any, // TODO: Revise in a future
    descriptor: DescriptorMap,
    expectedFormats: LdFormat & JwtFormat,
    endObjectFormats: LdFormat & JwtFormat
  ): Promise<VcJwtPayload> {
    const resolveDescriptor = async () => {
      if (currentDescriptor!.id && currentDescriptor!.id !== mainId) {
        // TODO: Define error type
        throw new Error("Each level of nesting of a descriptor map must have the same ID");
      }
      const path = currentDescriptor!.path ?? "$";
      if (!currentDescriptor!.format) {
        // TODO: Define error type
        throw new Error("MUST SPECIFY A FORMAT");
      }
      const validAlgs = this.checkFormatValidity(expectedFormats, currentDescriptor!.format);
      const tmp = jsonpath.query(currentTraversalObject, path, 1);
      if (!tmp.length) {
        // TODO: DEFINE ERROR TYPE
        throw new Error("PATH DOES NOT RESOLVE TO ANY DATA");
      }
      const parseResult = await this.decodeAndParse(currentDescriptor!.format, tmp[0], validAlgs);
      currentTraversalObject = parseResult.data;
      lastJwa = parseResult.jwa;
    }
    let currentDescriptor: DescriptorMap | undefined = descriptor;
    const mainId = currentDescriptor.id;
    if (!currentDescriptor.id) {
      // TODO: Define error type
      throw new Error("EACH DESCRIPTOR MUST HAVE AN ID");
    }
    let currentTraversalObject = data;
    let lastJwa: JWA_ALGS;
    let lastFormat;
    do {
      await resolveDescriptor();
      lastFormat = currentDescriptor.format;
      currentDescriptor = currentDescriptor.path_nested;
    } while (currentDescriptor);
    if (!currentTraversalObject.vc) {
      // TODO: Define error type
      // If Json Linked Data is implemented, the condicional expression should change
      throw new Error("Submission resolution did not resolve in a valid VC");
    }
    const validAlgs = this.checkFormatValidity(endObjectFormats, lastFormat);
    if (!validAlgs.includes(lastJwa))
      if ()
        return currentTraversalObject as VcJwtPayload;
  }

  async verifyPresentation(
    vp: any,
    definition: DIFPresentationDefinition,
    submission: DIFPresentationSubmission
  ) {
    if (definition.id !== submission.definition_id) {
      // TODO: ERROR
    }
    if (submission.descriptor_map.length !== definition.input_descriptors.length) {
      // TODO: ERROR
    }
    const idsAlreadyUsed = new Set<string>();
    for (const descriptor of submission.descriptor_map) {
      if (idsAlreadyUsed.has(descriptor.id)) {
        // TODO: ERROR -> Define error type
        throw new Error("Can't be two Descriptor with the same ID");
      }
      const inputDescriptor = this.findDefinitionInputDescriptor(definition, descriptor.id);
      const rootFormats = definition.format;
      const format = inputDescriptor.format ?? rootFormats;
      const vc = await this.extractCredentialFromVp(vp, descriptor, rootFormats, format);

    }
  }

  findDefinitionInputDescriptor(
    definition: DIFPresentationDefinition,
    id: string
  ): PresentationInputDescriptor {
    const result = definition.input_descriptors.find((descriptor) => descriptor.id === id);
    if (!result) {
      // TODO: Define errorr type
      throw new Error(`Invalid descriptor id: "${id}"`);
    }
    return result;
  }
}

// function checkIfLdFormat(data: LdFormat | JwtFormat): data is LdFormat {
//   return (data as LdFormat).ldp_vp !== undefined ||
//     (data as LdFormat).ldp_vc !== undefined ||
//     (data as LdFormat)["jwt_vc_json-ld"] !== undefined
// }

function checkIfLdFormat(
  format: W3CVerifiableCredentialFormats | W3CVerifiablePresentationFormats
) {
  return format.includes("ld");
}
