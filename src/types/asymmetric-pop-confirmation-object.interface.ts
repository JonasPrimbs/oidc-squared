import * as jose from 'jose';

export interface AsymmetricPoPConfirmationObject {

  /**
   * A public JSON Web Key.
   */
  jwk: jose.JWK;
}
