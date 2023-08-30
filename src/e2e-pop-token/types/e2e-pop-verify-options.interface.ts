import * as jose from 'jose';

export interface E2EPoPVerifyOptions extends jose.JWTVerifyOptions {

  /**
   * Maximum token age in seconds.
   */
  maxTokenAge?: number;

  /**
   * Expected Type.
   */
  typ?: 'jwt+e2epop';
}
