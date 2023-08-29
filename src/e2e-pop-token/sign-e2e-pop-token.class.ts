import * as jose from 'jose';
import { E2EPoPTokenHeader } from './e2e-pop-token-header.interface';
import { E2EPoPTokenPayload } from './e2e-pop-token-payload.interface';

export class SignE2EPoPToken extends jose.SignJWT {

  /**
   * Payload of the E2E PoP.
   */
  protected override _payload: Partial<E2EPoPTokenPayload> = {};

  /**
   * The SignE2EPoPToken class is used to build and sign End-to-End Proof-of-Possession Tokens (E2E PoPs).
   * @param payload Payload of the E2EPoP.
   */
  constructor(payload: Partial<E2EPoPTokenPayload>) {
    super(payload);
  }

  /**
   * Sets the protected E2E PoP header.
   * @param protectedHeader End-to-End Proof-of-Possession Token header.
   */
  public override setProtectedHeader(protectedHeader: E2EPoPTokenHeader): this {
    return super.setProtectedHeader(protectedHeader);
  }
}
