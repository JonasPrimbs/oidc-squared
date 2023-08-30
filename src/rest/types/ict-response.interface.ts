export interface ICTResponse {

  /**
   * The Identity Certification Token.
   */
  identity_certification_token: string;

  /**
   * In how many seconds the Identity Certification Token expires.
   */
  identity_certification_token_expires_in: number;

  /**
   * The authorized end-to-end contexts of the ICT.
   */
  e2e_auth_contexts: string[],
}
