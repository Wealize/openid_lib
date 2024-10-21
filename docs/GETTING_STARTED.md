<p align="center">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="./img/identfy-logo-dark.svg">
      <source media="(prefers-color-scheme: light)" srcset="./img/identfy-logo-light.svg">
      <img alt="identfy" src="./img/identfy.png" width="350" style="max-width: 100%;">
    </picture>
</p>

<p align="center">
  <h4>
    An all-in-one solution to take control of your digital identity
  </h4>
</p>

<br/>

#  identfy OpenID library

## Build

For the use of the library only Node with a version equal or higher than 16 is required.

### Test execution

The library comes with a battery of tests written with Mocha and Chai. To run them you will have to install the corresponding dependencies and transpile the TS code to JS with `npm run build`. Then you can run the tests with `npm run test`. It is also possible to do both steps with the same command `npm run build_and_test`.


## Overview of the code

### Capabilities
- Creation of authorization requests with different `response_type` (code and id_token).
- Validation of authorization requests.
- Issuance of access tokens
  - Support for `grant_type` "authorization_code".
  - Support for `grant_type` "pre-authorize_code".
- Issuance of W3C credentials for version 1 and 2 of the data model.
  - Verification of DIDs for control proofs.
  - Support for in-time flow.
  - Support for deferred flow.

### State management

The library requires the implementation of an interface with which to handle the states derived from the protocol. This proposed interface simulates the use of a key-value database, but its actual implementation depends entirely on the user.
The definition of this implementation is the first step to be taken in order to use the library and it is necessary both for the Authorization actions and for the issuance of credentials. The library offers a simple memory-based implementation that can be used for testing purposes, but is not recommended for production use. The name of this interface is ***StateManager***.

The management of a state implies that the operations have an order in which they must be carried out to ensure their correct functioning. In this case, the order corresponds to that indicated by the protocol, so that an ID token cannot be verified if one has not been generated first, for example.

### Algorithms and object signature

The library does not implement or support any cryptographic algorithms. Instead, this responsibility is left to the user. Consequently, the user is given the freedom to choose the solution that best suits the needs of the use case.

### Builders
The library defines multiple builders that can be used to generate authorization requests, `credential offers`, authorization details and also the metadata of a credential issuer. There is also a step builder that ca be used to create an instance of the RP.

### Relying Party

To manage the OpenID process for issuers or any other entity interested in authorization/authentication, the ***OpenIDReliyingParty*** class is defined. For its construction, the user should provide the metadata of the authorization service, an instance of ***DidResolver*** and a callback that allows to obtain the default metadata from the clients. The latter allows the metadata to be bound to the use case, eliminating the need for clients to specify it in full. In practice, the metadata implicitly specified by the user will be combined with the default metadata, the former prevailing over the latter.


```ts
const rp = new OpenIDReliyingParty(
    async () => {
      return {
        "authorization_endpoint": "openid:",
        "response_types_supported": ["vp_token", "id_token"],
        "vp_formats_supported": {
          "jwt_vp": {
            "alg_values_supported": ["ES256"]
          },
          "jwt_vc": {
            "alg_values_supported": ["ES256"]
          }
        },
        "jwt_vc": {
          "alg_values_supported": ["ES256"]
        }
      },
      "scopes_supported": ["openid"],
      "subject_types_supported": ["public"],
      "id_token_signing_alg_values_supported": ["ES256"],
      "request_object_signing_alg_values_supported": ["ES256"],
      "subject_syntax_types_supported": [
        "urn:ietf:params:oauth:jwk-thumbprint",
        "did:key:jwk_jcs-pub"
      ],
      "id_token_types_supported": ["subject_signed_id_token"]
    })
    .withDidResolver(new Resolver(getResolver()))
    .withTokenSignCallback((payload, algs) => {
      return signCallback(payload, algs);
    })
    .withStateManager(new MemoryStateManager())
    .build();
```

The Relying Party class currently allows the following:
- Validate Base Authz Request (AuthzRequest with "code" as response_type)
- Generate ID Token Request
- Validate ID Token Response
- Generate authorization code.
- Validate Token Request
- Generate Token Response

#### Verify Authz request with "code" as "response_type"
```ts
let verifiedAuthzRequest = await rp.verifyBaseAuthzRequest(
  authzRequest, // Authz Request from the client
);
```

#### Create ID Token Request
In order to do so, first we need to verify an Authz Request as indicated in the previous example
```ts

// Create ID Token Request
const idTokenRequest = await rp.createIdTokenRequest(
  verifiedAuthzRequest.authzRequest.client_metadata?.authorization_endpoint!,
  verifiedAuthzRequest.authzRequest.client_id,
  authServerUrl + "/direct_post",
  {
    type: "Issuance",
    verifiedBaseAuthzRequest: verifiedAuthzRequest,
  }
);
```

The call accepts the following optional parameters:
```ts
export type CreateIdTokenRequestOptionalParams = {
  /**
   * Response mode to specify in the ID Token
   * @defaultValue "direct_post"
   */
  responseMode?: AuthzResponseMode;
  /**
   * Additional payload to include in the JWT
   */
  additionalPayload?: Record<string, any>;
  /**
   * The state to indicate in the JWT
   */
  state?: string;
  /**
   * The expiration time of the JWT. Must be in seconds
   * @defaultValue 1 hour
   */
  expirationTime?: number;
  /**
   * The scope to include in the JWT
   */
  scope?: string
};
```

#### Verify ID Token Response
```ts
const verifiedIdTokenResponse = await rp.verifyIdTokenResponse(
  idTokenResponse, // ID Token response sent by a user
);
```
The method also generates an authorization code, that can be exchange for an access token in the next step.

#### Generate AccessToken / Token Response
```ts
// Create Token Request
const tokenRequest: TokenRequest = {
  grant_type: "authorization_code",
  client_id: holderDid,
  code_verifier: codeVerifier,
  code: verifiedIdTokenResponse.authzCode
};
// Create Token Response
const _tokenResponse = await rp.generateAccessToken(
  tokenRequest,
  false,
  signCallback,
  authServerUrl,
  authServerJWK
);
```

The method support both the authorization_code grant type and also, the pre-authorize one. However, only the first one is avaible by default. In order to be able to use pre-authorization codes, the user must specify it during the building phase of the RP using the setp builder, which will require a callback to be provided to redeem these codes.

#### Create VP Token Request
```ts
const vpRequest = await rp.createVpTokenRequest(
  verifiedAuthzRequest.authzRequest.client_metadata?.authorization_endpoint!,
  verifiedAuthzRequest.authzRequest.client_id,
  authServerUrl + "/direct_post",
  signCallback
);
```
The call accepts the following additional parameters:
```ts
export type CreateVpTokenRequestOptionalParams = {
  /**
 * Response mode to specify in the ID Token
 * @defaultValue "direct_post"
 */
  responseMode?: AuthzResponseMode;
  /**
   * Additional payload to include in the JWT
   */
  additionalPayload?: Record<string, any>;
  /**
   * The state to indicate in the JWT
   */
  state?: string;
  /**
   * The nonce to indicate in the JWT.
   * @defaultValue UUID randomly generated
   */
  nonce?: string;
  /**
   * The expiration time of the JWT. Must be in seconds
   * @defaultValue 1 hour
   */
  expirationTime?: number;
  /**
   * The scope to include in the JWT
   */
  scope?: string;
  /**
   * The presentation definition to include in the JWT
   */
  presentation_definition?: DIFPresentationDefinition;
  /**
   * The URI in which the presentation definition can be retrieved
   */
  presentation_definition_uri?: string
}
```

#### Verify VP Token Response
```ts
async function ValidNonceCallback() {
  // It is used to check the validity of the nonce contained inside the VP Token
  return { valid: true };
}
const presentationDefinition = getPresentationDefinition();
await rp.verifyVpTokenResponse(
  vpResponse,
  presentationDefinition,
  ValidNonceCallback
);
```

## Code of contribution

Read please the [contribution documentation](../CONTRIBUTING.md)