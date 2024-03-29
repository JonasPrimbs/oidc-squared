import * as jose from 'jose';
import { AsymmetricSigningAlgorithms } from '../../../types/asymmetric-signing-algorithms.type';

export interface ICTHeader extends jose.JWTHeaderParameters {

  /**
   * Type Header Parameter.
   */
  typ: 'jwt+ict';

  /**
   * Asymmetric JWS Signing Algorithm Header Parameter.
   */
  alg: AsymmetricSigningAlgorithms;

  /**
   * Key ID Header Parameter.
   */
  kid: string;
}
