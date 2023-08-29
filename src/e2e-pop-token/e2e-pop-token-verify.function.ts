import * as jose from 'jose';
import { E2EPoPTokenInvalid } from '../errors/e2e-pop-token-invalid.class';
import { AVAILABLE_ASYMMETRIC_SIGNING_ALGORITHMS } from '../types/asymmetric-signing-algorithms.type';
import { E2EPoPTokenHeader } from './e2e-pop-token-header.interface';
import { E2EPoPTokenPayload } from './e2e-pop-token-payload.interface';
import { E2EPoPVerifyOptions } from './e2e-pop-verify-options.interface';
import { E2EPoPVerifyResult } from './e2e-pop-verify-result.interface';

/**
 * Verifies an End-to-End Proof-of-Possession Token.
 * @param e2ePoPToken E2E PoP Token.
 * @param publicKey Public key from ICT to verify signature of.
 * @param options E2E PoP Token verification options.
 * @returns Header and payload of the successfully verified E2E PoP Token.
 */
export async function e2ePoPTokenVerify(e2ePoPToken: string, publicKey: jose.KeyLike, options: E2EPoPVerifyOptions = {}): Promise<E2EPoPVerifyResult> {
  // Validate options.
  if (!options.maxTokenAge || options.maxTokenAge <= 0) {
    options.maxTokenAge = 3600;
  } else if ((options.maxTokenAge ?? 0) > 3600) {
    console.warn(`Allowed maxTokenAge of an E2E PoP Token was set to "${options?.maxTokenAge}" which is longer than one hour. This is NOT RECOMMENDED!`);
  }

  // Verify JWT properties of ICT.
  const result = await jose.jwtVerify(e2ePoPToken, publicKey, options);

  // Verify header:
  const header = result.protectedHeader as Partial<E2EPoPTokenHeader>;
  if (header.typ !== 'jwt+e2epop') {
    throw new E2EPoPTokenInvalid(`Type of E2E PoP Token is not "jwt+e2epop"! Value was "${header.typ}"`);
  }
  if (AVAILABLE_ASYMMETRIC_SIGNING_ALGORITHMS.indexOf(header.alg ?? '') < 0) {
    throw new E2EPoPTokenInvalid(`E2E PoP Token uses the unsupported signing algorithm "${header.alg}"`);
  }
  if (!header.jkt) {
    throw new E2EPoPTokenInvalid('E2E PoP MUST provide a "jkt" (JWK Thumbprint) parameter in header');
  } else if (header.jkt !== await jose.calculateJwkThumbprint(publicKey)) {
    throw new E2EPoPTokenInvalid(`The JWK Thumbprint of the provided public key does not match the expected JWK Thumbprint "${header.jkt}" from the "jkt" header of the E2E PoP Token`);
  }

  // Verify payload:
  const payload = result.payload as Partial<E2EPoPTokenPayload>;

  // Verify existance of required E2E PoP Token claims:
  if (!payload.sub) {
    throw new E2EPoPTokenInvalid('E2E PoP Tokens MUST contain a "sub" (Subject) claim');
  }
  if (!payload.iss) {
    throw new E2EPoPTokenInvalid('E2E PoP Tokens MUST contain an "iss" (Issuer) claim');
  }
  if (!payload.aud) {
    throw new E2EPoPTokenInvalid('E2E PoP Tokens MUST contain a valid "aud" (Audience) claim');
  }
  if (!payload.jti) {
    throw new E2EPoPTokenInvalid('E2E PoP Tokens MUST contain a "jti" (JWT ID) claim');
  }
  if (!payload.iat) {
    throw new E2EPoPTokenInvalid('E2E PoP Tokens MUST contain an "iat" (Issued At) claim');
  }
  if (!payload.exp) {
    throw new E2EPoPTokenInvalid('E2E PoP Tokens MUST contain an "exp" (Expiration) claim');
  }

  // Return result.
  return {
    protectedHeader: result.protectedHeader as E2EPoPTokenHeader,
    payload: payload as E2EPoPTokenPayload,
  };
}
