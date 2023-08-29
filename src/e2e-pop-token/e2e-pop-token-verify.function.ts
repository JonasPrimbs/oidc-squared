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
export async function e2ePoPTokenVerify(e2ePoPToken: string, publicKey: jose.KeyLike | Uint8Array, options: E2EPoPVerifyOptions = {}): Promise<E2EPoPVerifyResult> {
  // Validate options.
  if (!options.maxTokenAge || options.maxTokenAge <= 0) {
    options.maxTokenAge = 3600;
  } else if ((options.maxTokenAge ?? 0) > 3600) {
    console.warn(`Allowed maxTokenAge of an E2E PoP Token was set to "${options?.maxTokenAge}" which is longer than one hour. This is NOT RECOMMENDED!`);
  }
  options.typ = 'jwt+e2epop';
  // Ensure that algorithms are supported.
  if (options.algorithms) {
    options.algorithms = options.algorithms.filter(alg => AVAILABLE_ASYMMETRIC_SIGNING_ALGORITHMS.indexOf(alg) >= 0);
  } else {
    options.algorithms = AVAILABLE_ASYMMETRIC_SIGNING_ALGORITHMS;
  }
  // Set required claims.
  options.requiredClaims = [
    ...(options.requiredClaims ?? []),
    'sub',
    'iss',
    'aud',
    'jti',
    'iat',
    'exp',
  ];

  // Verify JWT properties of ICT.
  const result = await jose.jwtVerify(e2ePoPToken, publicKey, options);

  // Verify header:
  const header = result.protectedHeader as Partial<E2EPoPTokenHeader>;
  if (AVAILABLE_ASYMMETRIC_SIGNING_ALGORITHMS.indexOf(header.alg ?? '') < 0) {
    throw new E2EPoPTokenInvalid(`E2E PoP Token uses the unsupported signing algorithm "${header.alg}"`);
  }
  if (!header.jkt) {
    throw new E2EPoPTokenInvalid('E2E PoP MUST provide a "jkt" (JWK Thumbprint) parameter in header');
  } else if (header.jkt !== await jose.calculateJwkThumbprint(await jose.exportJWK(publicKey))) {
    throw new E2EPoPTokenInvalid(`The JWK Thumbprint of the provided public key does not match the expected JWK Thumbprint "${header.jkt}" from the "jkt" header of the E2E PoP Token`);
  }

  // Return result.
  return {
    protectedHeader: result.protectedHeader as E2EPoPTokenHeader,
    payload: result.payload as E2EPoPTokenPayload,
  };
}
