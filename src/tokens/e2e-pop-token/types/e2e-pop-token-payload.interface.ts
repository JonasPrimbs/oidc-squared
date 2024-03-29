import * as jose from 'jose';

export interface E2EPoPTokenPayload extends jose.JWTPayload {

  /**
   * JWT Issuer.
   * 
   * Typically the Client ID of the End-User's Client.
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
   * Typically the Client ID or User ID that the Authenticating Party uniquely identifies with.
   */
  aud: string | string[];

  /**
   * JWT ID.
   * 
   * A randomly generated string that is unique for the combination of issuer, subject, and audience within the lifespan of the ICT.
   */
  jti: string;

  /**
   * JWT Issued At.
   * 
   * The seconds-precision Unix timestamp when the E2E PoP Token was issued.
   */
  iat: number;

  /**
   * JWT Not Before.
   * 
   * The seconds-precision Unix timestamp when the E2E PoP Token becomes valid.
   */
  nbf?: number;

  /**
   * JWT Expiration Time.
   * 
   * The seconds-precision Unix timestamp when the E2E PoP Token expires.
   */
  exp: number;
}
