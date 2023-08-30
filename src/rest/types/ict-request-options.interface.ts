export interface ICTRequestOptions {

  /**
   * URL of the ICT Endpoint.
   */
  ictEndpoint: string;

  /**
   * OAuth Access Token to proof authorization.
   */
  accessToken: string;

  /**
   * Proof-of-possession token to provide public key and prove possession of the corresponding private key.
   */
  popToken: string;

  /**
   * Array of required identity claims.
   */
  requiredClaims: string[];

  /**
   * Array of optional identity claims.
   */
  optionalClaims: string[];
}
