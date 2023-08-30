import * as jose from 'jose';
import { AsymmetricSigningAlgorithms } from '../../types/asymmetric-signing-algorithms.type';
import { NonceGenerators } from '../../nonce-generators/nonce-generators.class';
import { E2EPoPTokenHeader } from './types/e2e-pop-token-header.interface';
import { E2EPoPTokenPayload } from './types/e2e-pop-token-payload.interface';

export class SignE2EPoPToken extends jose.SignJWT {

  /**
   * Payload of the E2E PoP.
   */
  protected override _payload: Partial<E2EPoPTokenPayload> = {};

  /**
   * The SignE2EPoPToken class is used to build and sign End-to-End Proof-of-Possession Tokens (E2E PoPs).
   * @param payload Payload of the E2EPoP.
   */
  constructor(payload?: Partial<E2EPoPTokenPayload>) {
    super(payload ?? {});
    this.setJti();
    this.setIssuedAt();
  }

  /**
   * Sets the protected E2E PoP header.
   * @param protectedHeader End-to-End Proof-of-Possession Token header.
   */
  public override setProtectedHeader(protectedHeader: E2EPoPTokenHeader): this {
    return super.setProtectedHeader(protectedHeader);
  }

  /**
   * Set "iat" (Issued At) Claim and sets the "exp" (Expiration) Claim to the recommended 300 seconds later, if not yet set.
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
   * Sets the JWK Thumbprint of the key that the E2E PoP Token will be signed with.
   * @param alg JWA signing algorithm.
   * @param jkt JWK Thumbprint of the Client's public key.
   */
  public setThumbprint(alg: AsymmetricSigningAlgorithms, jkt: string): this {
    return this.setProtectedHeader({
      typ: 'jwt+e2epop',
      alg: alg,
      jkt: jkt,
    });
  }
}
