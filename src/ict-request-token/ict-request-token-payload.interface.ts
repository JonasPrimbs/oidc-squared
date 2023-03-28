import { IrtClaimsSpecification } from './irt-claims-specification.interface';

export interface IctRequestTokenPayload {

  /**
   * Issuer of the ID Certification Token.
   */
  iss: string;

  /**
   * Subject of the ID Certification Token.
   */
  sub: string;

  /**
   * Audience of the ID Certification Token.
   */
  aud: string | string[];

  /**
   * JSON Web Token ID.
   */
  jti?: string;

  /**
   * A unique random nonce.
   */
  nonce?: string;

  /**
   * Unix timestamp with seconds precision of the issued at date.
   */
  iat: number;

  /**
   * Unix timestamp with seconds precision of the not before date.
   */
  nbf?: number;

  /**
   * Unix timestamp with seconds precision of the expiration date.
   */
  exp: number;

  /**
   * Specification of desired claims in the requested ID Certification Token.
   */
  token_claims?: IrtClaimsSpecification;
}
