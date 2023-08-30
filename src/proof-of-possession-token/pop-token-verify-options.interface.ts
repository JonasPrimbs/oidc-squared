import * as jose from 'jose';

export interface PoPTokenVerifyOptions extends jose.JWTVerifyOptions {

  /**
   * Maximum token age in seconds.
   */
  maxTokenAge?: number;

  /**
   * Expected Type.
   */
  typ?: 'jwt+pop';
}
