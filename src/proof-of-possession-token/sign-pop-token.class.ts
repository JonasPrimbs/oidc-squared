import * as jose from 'jose';
import { PoPTokenHeader } from './types/pop-token-header.interface';
import { PoPTokenPayload } from './types/pop-token-payload.interface';

export class SignPoPToken extends jose.SignJWT {

  /**
   * Payload of the PoP Token.
   */
  protected override _payload: Partial<PoPTokenPayload> = {};

  /**
   * The SignPoPToken class is used to build and sign Proof-of-Possession Tokens.
   * @param payload Payload of the PoP Token.
   */
  constructor(payload?: Partial<PoPTokenPayload>) {
    super(payload ?? {});
  }

  /**
   * Set "aud" (Audience) Claim.
   * @param audience "aud" (Audience) Claim value to set on the JWT Claims Set.
   */
  public override setAudience(audience: string): this {
    return super.setAudience(audience);
  }

  /**
   * Sets the protected PoP Token header.
   * @param protectedHeader Proof of Possession Token header.
   */
  public override setProtectedHeader(protectedHeader: PoPTokenHeader): this {
    return super.setProtectedHeader(protectedHeader);
  }
}
