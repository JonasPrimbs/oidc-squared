import * as jose from 'jose';
import { AsymmetricSigningAlgorithms } from '../../../types/asymmetric-signing-algorithms.type';

export interface PoPTokenHeader extends jose.JWTHeaderParameters {

  /**
   * Type Header Parameter.
   */
  typ: 'jwt+pop';

  /**
   * Asymmetric JWS Signing Algorithm Header Parameter.
   */
  alg: AsymmetricSigningAlgorithms;

  /**
   * JSON Web Key Header Parameter.
   * 
   * This key must be used to sign the PoP Token.
   */
  jwk: Pick<jose.JWK, 'kty' | 'crv' | 'x' | 'y' | 'e' | 'n'>;
}
