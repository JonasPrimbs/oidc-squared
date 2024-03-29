import * as jose from 'jose';

export interface ICTVerifyOptions extends jose.JWTVerifyOptions {

  /**
   * Maximum token age in seconds.
   */
  maxTokenAge?: number;

  /**
   * Required end-to-end authentication context.
   */
  requiredContext?: string | string[];

  /**
   * Expected Type.
   */
  typ?: 'jwt+ict';
}
