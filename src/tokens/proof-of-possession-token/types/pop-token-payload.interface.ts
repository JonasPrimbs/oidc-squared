import * as jose from 'jose';

export interface PoPTokenPayload extends jose.JWTPayload {

  /**
   * JWT Issuer.
   * 
   * Typically the Client ID.
   */
  iss: string;

  /**
   * JWT Subject.
   * 
   * Typically the identifier of the End-User.
   */
  sub: string;

  /**
   * JWT Audience.
   * 
   * Typically the base URL of the OpenID Provider.
   */
  aud: string;

  /**
   * JWT ID.
   * 
   * A randomly generated string that is unique for the combination of issuer, subject and audience within the lifespan of the PoP Token.
   */
  jti: string;

  /**
   * JWT Issued At.
   * 
   * The seconds-precision Unix timestamp when the PoP Token was issued.
   */
  iat: number;

  /**
   * JWT Not Before.
   * 
   * The seconds-precision Unix timestamp when the PoP Token becomes valid.
   */
  nbf?: number;

  /**
   * JWT Expiration Time.
   * 
   * The seconds-precision Unix timestamp when the PoP Token expires.
   */
  exp: number;

  /**
   * Array of required identity claims.
   */
  requiredClaims?: string[];

  /**
   * Array of optional identity claims.
   */
  optionalClaims?: string[];

  /**
   * Whether the audience should be present.
   * @default true
   */
  withAudience?: boolean;
}
