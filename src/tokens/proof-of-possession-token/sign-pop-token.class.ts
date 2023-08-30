import * as jose from 'jose';
import { PoPTokenHeader } from './types/pop-token-header.interface';
import { PoPTokenPayload } from './types/pop-token-payload.interface';
import { AsymmetricSigningAlgorithms, NonceGenerators } from '../..';

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
    this.setJti();
    this.setIssuedAt();
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

  /**
   * Set "iat" (Issued At) Claim and sets the "exp" (Expiration) Claim to the recommended 60 seconds later, if not yet set.
   * @param input "iat" (Issued At) Claim value to set on the JWT Claim Set or undefined to use now.
   */
  override setIssuedAt(input?: number | undefined): this {
    const iatResult = super.setIssuedAt(input);
    if (iatResult._payload.exp) {
      return iatResult;
    } else {
      return super.setExpirationTime(iatResult._payload.iat! + 60);
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
   * Sets the public key of the PoP Token.
   * @param alg JWA signing algorithm.
   * @param jwk Public JSON Web Key.
   */
  public setPublicKey(alg: AsymmetricSigningAlgorithms, jwk: Pick<jose.JWK, 'kty' | 'crv' | 'x' | 'y' | 'e' | 'n'>): this {
    return this.setProtectedHeader({
      typ: 'jwt+pop',
      alg: alg,
      jwk: jwk,
    });
  }
}
