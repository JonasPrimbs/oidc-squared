import * as jose from 'jose';
import { AsymmetricSigningAlgorithms } from '../../../types/asymmetric-signing-algorithms.type';

export interface E2EPoPTokenHeader extends jose.JWTHeaderParameters {

  /**
   * Type Header Parameter.
   */
  typ: 'jwt+e2epop';

  /**
   * Asymmetric JWS Signing Algorithm Header Parameter.
   */
  alg: AsymmetricSigningAlgorithms;

  /**
   * JSON Web Key Thumbprint (JKT) Header Parameter.
   * 
   * This is MUST be the JWK Thumbprint of the JWK from the confirmation claim of the ICT.
   */
  jkt: string;
}
