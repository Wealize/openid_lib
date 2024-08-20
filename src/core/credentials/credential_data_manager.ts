import { W3CVerifiableCredentialFormats } from "../../common";
import { Result } from "../../common/classes/result";
import {
  CredentialDataResponse,
  DeferredCredentialData,
  InTimeCredentialData
} from "./types";

/**
 * Abstract class that provided an interface to a VC Issuer
 * thorugh which it can get the information related to a VC
 */
export abstract class CredentialDataManager {
  /**
   * Allows to get all the related data to a VC, like the credentialSubject data,
   * the terms of use and the status information.
   * @param types The types of the VC
   * @param holder The future holder of the VC
   */
  abstract getCredentialData(
    types: string[],
    holder: string
  ): Promise<CredentialDataResponse>;

  // TODO: Set VC format. This callback could fail if the acceptance token is wrong
  /**
   * Allows to exchange an acepptance Token of a deferred flow for another one or for
   * a VC if it is already available
   * @param acceptanceToken The token to exchange
   */
  abstract deferredExchange(
    acceptanceToken: string
  ): Promise<
    Result<
      InTimeCredentialData & { format: W3CVerifiableCredentialFormats }
      | DeferredCredentialData, Error
    >
  >;

  /**
   * Allows to obtain the true identifier of the credential subject. This method
   * can be overwritten if needed and be useful when working with DID URL syntax
   * @param _accessTokenSubject The subject ID contained in an Access Token
   * @param proofIssuer The subject ID contained in a control proof
   * @returns 
   */
  async resolveCredentialSubject(
    _accessTokenSubject: string,
    proofIssuer: string
  ): Promise<string> {
    return proofIssuer;
  }
}
