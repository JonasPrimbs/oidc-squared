import * as crypto from 'crypto';

import { JwsSignatureAlgorithm } from '../types/jws-signature-algorithm.type';
import { JwtTypeIrt } from '../types';

export interface IctRequestTokenHeader {
  /**
   * Signing algorithm of the ICT Request Token.
   */
  alg: JwsSignatureAlgorithm;

  /**
   * Type of the JWT.
   */
  typ: JwtTypeIrt;

  /**
   * Public Key that the ICT Request Token is signed with.
   */
  jwk: crypto.webcrypto.JsonWebKey;
}
