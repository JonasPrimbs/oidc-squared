import * as jose from 'jose';
import { PoPTokenHeader } from './pop-token-header.interface';
import { PoPTokenPayload } from './pop-token-payload.interface';

export interface PoPTokenVerifyResult extends jose.JWTVerifyResult {

  /**
   * Protected JWT header.
   */
  protectedHeader: PoPTokenHeader;

  /**
   * ICT Claims Set.
   */
  payload: PoPTokenPayload;
}
