import * as jose from 'jose';
import { ICTHeader } from './types/ict-header.interface';
import { ICTPayload } from './types/ict-payload.interface';

export class SignICT extends jose.SignJWT {

  /**
   * Payload of the ICT.
   */
  protected override _payload: Partial<ICTPayload> = {};

  /**
   * The SignICT class is used to build and sign Identity Certification Tokens (ICTs).
   * @param payload Payload of the ICT.
   */
  constructor(payload?: Partial<ICTPayload>) {
    super(payload ?? {});
  }

  /**
   * Set "cnf" (Confirmation) Claim.
   * @param publicKey The public "jwk" (JSON Web Key) parameter being present in the "cnf" (Confirmation) Claim.
   */
  public setConfirmation(publicKey: jose.JWK): this {
    this._payload.cnf = {
      jwk: publicKey,
    };

    return this;
  }

  /**
   * Set "ctx" (End-to-End Authentication Context(s)) Claim.
   * @param context "ctx" (End-to-End Authentication Context(s)) Claim value set on the ICT payload.
   */
  public setContext(context: string | string[]): this {
    this._payload.ctx = context;

    return this;
  }

  /**
   * Sets the protected ICT header.
   * @param protectedHeader Proof of Possession Token header.
   */
  public override setProtectedHeader(protectedHeader: ICTHeader): this {
    return super.setProtectedHeader(protectedHeader);
  }
}
