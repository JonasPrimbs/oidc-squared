import * as jose from 'jose';
import { ConfirmationObject } from '../../../types/confirmation-object.type';

export interface ICTPayload extends jose.JWTPayload {

  /**
   * JWT Issuer.
   * 
   * Typically the base URL of the OpenID Provider.
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
   * Typically the Client ID of the End-User's Client.
   */
  aud?: string | string[];

  /**
   * JWT ID.
   * 
   * A randomly generated string that is unique for the combination of issuer and subject within the lifespan of the ICT.
   */
  jti: string;

  /**
   * JWT Issued At.
   * 
   * The seconds-precision Unix timestamp when the ICT was issued.
   */
  iat: number;

  /**
   * JWT Not Before.
   * 
   * The seconds-precision Unix timestamp when the ICT becomes valid.
   */
  nbf?: number;

  /**
   * JWT Expiration Time.
   * 
   * The seconds-precision Unix timestamp when the ICT expires.
   */
  exp: number;

  /**
   * JWT Confirmation.
   * 
   * Contains the verified public key of the Client.
   */
  cnf: ConfirmationObject;

  /**
   * JWT End-to-End Context.
   * 
   * A string or array of strings which define the granted authentication context of the ICT.
   */
  ctx: string | string[];
}
