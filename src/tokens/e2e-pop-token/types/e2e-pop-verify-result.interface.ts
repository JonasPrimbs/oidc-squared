import * as jose from 'jose';
import { E2EPoPTokenHeader } from './e2e-pop-token-header.interface';
import { E2EPoPTokenPayload } from './e2e-pop-token-payload.interface';

export interface E2EPoPVerifyResult extends jose.JWTVerifyResult {

  /**
   * Protected JWT header.
   */
  protectedHeader: E2EPoPTokenHeader;

  /**
   * E2E PoP Token Claims set.
   */
  payload: E2EPoPTokenPayload;
}
