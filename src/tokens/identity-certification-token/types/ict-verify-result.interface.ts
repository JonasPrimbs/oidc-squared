import * as jose from 'jose';
import { ICTHeader } from './ict-header.interface';
import { ICTPayload } from './ict-payload.interface';

export interface ICTVerifyResult extends jose.JWTVerifyResult {

  /**
   * Protected JWT header.
   */
  protectedHeader: ICTHeader;

  /**
   * ICT Claims Set.
   */
  payload: ICTPayload;
}
