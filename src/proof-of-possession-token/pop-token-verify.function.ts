import * as jose from 'jose';
import { AVAILABLE_ASYMMETRIC_SIGNING_ALGORITHMS } from '../types/asymmetric-signing-algorithms.type';
import { PoPTokenHeader } from './pop-token-header.interface';
import { PoPTokenInvalid } from './pop-token-invalid.interface';
import { PoPTokenPayload } from './pop-token-payload.interface';
import { PoPTokenVerifyOptions } from './pop-token-verify-options.interface';
import { PoPTokenVerifyResult } from './pop-token-verify-result.interface';

export async function popTokenVerify(popToken: string | Uint8Array, options: PoPTokenVerifyOptions = {}): Promise<PoPTokenVerifyResult> {
  // Validate options.
  if (!options.maxTokenAge || options.maxTokenAge <= 0) {
    options.maxTokenAge = 300;
  } else if ((options.maxTokenAge ?? 0) > 300) {
    console.warn(`Allowed maxTokenAge of a PoP Token was set to "${options?.maxTokenAge}" which is longer than 5 minutes. This is NOT RECOMMENDED!`);
  }
  options.typ = 'jwt+pop';
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

  // Verify JWT Properties of PoP Token.
  const result = await jose.jwtVerify(popToken, jose.EmbeddedJWK, options);

  // Verify header:
  const header = result.protectedHeader as Partial<PoPTokenHeader>;
  if (AVAILABLE_ASYMMETRIC_SIGNING_ALGORITHMS.indexOf(header.alg ?? '') < 0) {
    throw new PoPTokenInvalid(`PoP Token uses the unsupported signing algorithm "${header.alg}"`);
  }
  if (!header.jwk) {
    throw new PoPTokenInvalid('PoP Token MUST provide a "jwk" (JSON Web Key) parameter in header containing the public key of the issuer');
  }

  // Verify payload:
  const payload = result.payload as Partial<PoPTokenPayload>;

  // Return result.
  return {
    protectedHeader: header as PoPTokenHeader,
    payload: payload as PoPTokenPayload,
  };
}
