import * as jose from 'jose';
import { ICTHeader } from './types/ict-header.interface';
import { ICTPayload } from './types/ict-payload.interface';
import { NonceGenerators } from '../../nonce-generators/nonce-generators.class';
import { AsymmetricSigningAlgorithms } from '../..';

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
    this.setJti();
    this.setIssuedAt();
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

  /**
   * Set "iat" (Issued At) Claim and sets the "exp" (Expiration) Claim to the recommended 60 seconds later, if not yet set.
   * @param input "iat" (Issued At) Claim value to set on the JWT Claim Set or undefined to use now.
   */
  override setIssuedAt(input?: number | undefined): this {
    const iatResult = super.setIssuedAt(input);
    if (iatResult._payload.exp) {
      return iatResult;
    } else {
      return super.setExpirationTime(iatResult._payload.iat! + 300);
    }
  }

  /**
   * Set "jti" (JWT ID) Claim.
   * @param jwtId "jti" (JWT ID) Claim value to set on the JWT Claim Set or undefined to use a UUID.
   */
  override setJti(jwtId?: string): this {
    return super.setJti(jwtId ?? NonceGenerators.uuid().generate());
  }

  /**
   * Sets the Key ID of the key that the ICT will be signed with.
   * @param alg JWA signing algorithm.
   * @param kid Key ID.
   */
  public setKeyId(alg: AsymmetricSigningAlgorithms, kid: string): this {
    return this.setProtectedHeader({
      typ: 'jwt+ict',
      alg: alg,
      kid: kid,
    });
  }
}
