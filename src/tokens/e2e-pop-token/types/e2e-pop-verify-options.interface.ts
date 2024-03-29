import * as jose from 'jose';

export interface E2EPoPVerifyOptions extends jose.JWTVerifyOptions {

  /**
   * Subject Identifier.
   * It MUST match the Subject Claim from the ICT.
   */
  subject: string;

  /**
   * Maximum token age in seconds.
   */
  maxTokenAge?: number;

  /**
   * Expected Type.
   */
  typ?: 'jwt+e2epop';
}
