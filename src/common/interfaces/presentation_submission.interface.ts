import {
  W3CVerifiableCredentialFormats,
  W3CVerifiablePresentationFormats
} from "../formats"

export interface DIFPresentationSubmission {
  id: string,
  definition_id: string,
  descriptor_map: DescriptorMap[]
}

export interface DescriptorMap {
  id: string,
  format: W3CVerifiableCredentialFormats | W3CVerifiablePresentationFormats,
  path?: string,
  path_nested?: DescriptorMap
}
