import { v4 as uuidv4 } from 'uuid';
import { Resolver } from "did-resolver";
import { JWK } from "jose";
import { Jwt, JwtPayload } from "jsonwebtoken";
import { ControlProof } from "common/classes/control_proof";
import { CONTEXT_VC_DATA_MODEL_2, C_NONCE_EXPIRATION_TIME } from "common/constants";
import { W3CVerifiableCredentialFormats } from "common/formats";
import { CredentialRequest } from "common/interfaces/credential_request.interface";
import { IssuerMetadata } from "common/interfaces/issuer_metadata.interface";
import {
  W3CVcSchemaDefinition,
} from "common/interfaces/w3c_verifiable_credential.interface";
import { decodeToken, verifyJwtWithExpAndAudience } from "common/utils/jwt.utils";
import { VcFormatter } from './formatters';
import { CredentialResponse } from 'common/interfaces/credential_response.interface';
import * as VcIssuerTypes from "./types";
import { InsufficienteParamaters, InternalError, InvalidCredentialRequest, InvalidToken } from 'common/classes';

export class W3CVcIssuer {
  constructor(
    private metadata: IssuerMetadata,
    private didResolver: Resolver,
    private issuerDid: string,
    private signCallback: VcIssuerTypes.VcSignCallback,
    private cNonceRetrieval: VcIssuerTypes.ChallengeNonceRetrieval,
    private getVcSchema: VcIssuerTypes.GetCredentialSchema,
    private getCredentialData: VcIssuerTypes.GetCredentialData,
  ) { }

  async verifyAccessToken(
    token: string,
    publicKeyJwkAuthServer: JWK,
    tokenVerifyCallback: VcIssuerTypes.AccessTokenVerifyCallback
  ): Promise<Jwt> {
    await verifyJwtWithExpAndAudience(token, publicKeyJwkAuthServer, this.metadata.credential_issuer);
    const jwt = decodeToken(token);
    const verificationResult = await tokenVerifyCallback(jwt.header, jwt.payload as JwtPayload);
    if (!verificationResult.valid) {
      throw new InvalidToken(
        `Invalid access token provided${verificationResult.error ? ": " + verificationResult.error : '.'}`
      );
    }
    return jwt;
  }

  async generateCredentialResponse(
    acessToken: string | Jwt,
    credentialRequest: CredentialRequest,
    optionalParamaters?: VcIssuerTypes.GenerateCredentialReponseOptionalParams
  ): Promise<CredentialResponse> {
    if (typeof acessToken === "string") {
      if (!optionalParamaters || !optionalParamaters.tokenVerification) {
        throw new InsufficienteParamaters(`"tokenVerification" optional parameter must be set when acessToken is in string format`);
      }
      acessToken = await this.verifyAccessToken(
        acessToken,
        optionalParamaters.tokenVerification.publicKeyJwkAuthServer,
        optionalParamaters.tokenVerification.tokenVerifyCallback
      );
    }
    this.checkCredentialTypesAndFormat(credentialRequest.types, credentialRequest.format);
    const controlProof = ControlProof.fromJSON(credentialRequest.proof);
    const proofAssociatedClient = controlProof.getAssociatedIdentifier();
    const jwtPayload = acessToken.payload as JwtPayload;
    if (proofAssociatedClient !== jwtPayload.sub) {
      throw new InvalidToken(
        "Access Token was issued for a different identifier that the one that sign the proof"
      );
    }
    const cNonce = await this.cNonceRetrieval(jwtPayload.sub);
    await controlProof.verifyProof(cNonce,
      this.metadata.credential_issuer,
      this.didResolver
    );
    const credentialDataOrDeferred = await this.getCredentialData(
      credentialRequest.types,
      jwtPayload.sub
    );
    if (credentialDataOrDeferred.deferredCode) {
      return {
        acceptance_token: credentialDataOrDeferred.deferredCode
      }
    } else if (credentialDataOrDeferred.data) {
      return this.generateW3CCredential(
        credentialRequest.types,
        await this.getVcSchema(credentialRequest.types),
        jwtPayload.sub,
        credentialDataOrDeferred.data,
        credentialRequest.format,
        optionalParamaters
      );
    } else {
      throw new InternalError("No credential data or deferred code received");
    }
  }

  private async generateW3CCredential(
    type: string[],
    schema: W3CVcSchemaDefinition[],
    subject: string,
    vcData: Record<string, any>,
    format: W3CVerifiableCredentialFormats,
    optionalParameters?: VcIssuerTypes.BaseOptionalParams,
  ): Promise<CredentialResponse> {
    const vcId = uuidv4();
    const formatter = VcFormatter.fromVcFormat(format);
    const vcPreSign = formatter.formatVc({
      "@context": CONTEXT_VC_DATA_MODEL_2,
      type,
      credentialSchema: schema,
      validFrom: new Date().toISOString(),
      validUntil: (optionalParameters && optionalParameters.getValidUntil) ?
        await optionalParameters.getValidUntil(
          type
        ) : undefined,
      id: vcId,
      credentialStatus: (optionalParameters && optionalParameters.getCredentialStatus) ?
        await optionalParameters.getCredentialStatus(
          type,
          vcId,
          subject
        ) : undefined,
      issuer: this.issuerDid,
      credentialSubject: {
        id: subject,
        ...vcData
      }
    });
    const signedVc = await this.signCallback(format, vcPreSign);
    return {
      format: format,
      credential: signedVc,
      c_nonce: (optionalParameters &&
        optionalParameters.cNonceToEmploy) ? optionalParameters.cNonceToEmploy : uuidv4(),
      c_nonce_expires_in: (optionalParameters &&
        optionalParameters.cNonceExp) ? optionalParameters.cNonceExp : C_NONCE_EXPIRATION_TIME
    }
  }

  async exchangeAcceptanceTokenForVc(
    acceptanceToken: string,
    deferredExchangeCallback: VcIssuerTypes.DeferredExchangeCallback,
    optionalParameters?: VcIssuerTypes.BaseOptionalParams,
  ): Promise<CredentialResponse> {
    const exchangeResult = await deferredExchangeCallback(acceptanceToken);
    if ("error" in exchangeResult) {
      throw new InvalidToken(`Invalid acceptance token: ${exchangeResult.error}`);
    }
    if (exchangeResult.deferredCode) {
      return { acceptance_token: exchangeResult.deferredCode };
    }
    return this.generateW3CCredential(
      exchangeResult.types,
      await this.getVcSchema(exchangeResult.types),
      exchangeResult.subject,
      exchangeResult.data!,
      exchangeResult.format,
      optionalParameters
    );
  }

  private checkCredentialTypesAndFormat(types: string[], format: W3CVerifiableCredentialFormats) {
    const typesSet = new Set(types);
    for (const credentialSupported of this.metadata.credentials_supported) {
      const supportedSet = new Set(credentialSupported.types);
      if ([...typesSet].every((item) => supportedSet.has(item)) && credentialSupported.format === format) {
        return;
      }
    }
    throw new InvalidCredentialRequest("Unsuported combination of credential types and format");
  }
}
