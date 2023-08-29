import * as jose from 'jose';
import { ICTInvalid } from '../errors/ict-invalid.class';
import { AVAILABLE_ASYMMETRIC_SIGNING_ALGORITHMS } from '../types/asymmetric-signing-algorithms.type';
import { ICTHeader } from './ict-header.interface';
import { ICTPayload } from './ict-payload.interface';
import { ICTVerifyOptions } from './ict-verify-options.interface';
import { ICTVerifyResult } from './ict-verify-result.interface';

/**
 * Verifies an Identity Certification Token.
 * @param ict Identity Certification Token.
 * @param publicKey Public key of OpenID Provider to verify the signature with.
 * @param options ICT verification options.
 * @returns Header and payload of successfully verified ICT.
 */
export async function ictVerify(ict: string | Uint8Array, publicKey: jose.KeyLike | Uint8Array, options: ICTVerifyOptions = {}): Promise<ICTVerifyResult> {
  // Validate options.
  if (!options.maxTokenAge || options.maxTokenAge <= 0) {
    options.maxTokenAge = 3600;
  } else if ((options.maxTokenAge ?? 0) > 3600) {
    console.warn(`Allowed maxTokenAge of an ICT was set to "${options?.maxTokenAge}" which is longer than one hour. This is NOT RECOMMENDED!`);
  }
  if (!options.requiredContext) {
    console.warn('No end-to-end authentication context provided. This is NOT RECOMMENDED!');
  }
  options.typ = 'jwt+ict';
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
    'jti',
    'iat',
    'exp',
    'cnf',
    'ctx',
  ];

  // Verify JWT properties of ICT.
  const result = await jose.jwtVerify(ict, publicKey, options);

  // Verify header:
  const header = result.protectedHeader as Partial<ICTHeader>;
  if (AVAILABLE_ASYMMETRIC_SIGNING_ALGORITHMS.indexOf(header.alg ?? '') < 0) {
    throw new ICTInvalid(`ICT uses the unsupported signing algorithm "${header.alg}"`);
  }
  if (!header.kid) {
    throw new ICTInvalid('ICT MUST provide a "kid" (Key ID) parameter in header');
  }

  // Verify payload:
  const payload = result.payload as ICTPayload;

  // Verify that cnf claim contains the jwk parameter.
  if (!payload.cnf.jwk) {
    throw new ICTInvalid('ICTs MUST contain a "jwk" (JSON Web Key) parameter in their "cnf" (Confirmation) claim');
  }

  // Verify ICT contexts:
  const requiredContexts = (typeof options.requiredContext === 'string') ? [options.requiredContext] : options.requiredContext ?? [];
  const providedContexts = (typeof payload.ctx === 'string') ? [payload.ctx] : payload.ctx ?? [];
  if (!requiredContexts.every((context) => providedContexts.indexOf(context) >= 0)) {
    throw new ICTInvalid(`ICT does not contain all required end-to-end authentication contexts! Required: ${JSON.stringify(requiredContexts)}. Contained: ${JSON.stringify(providedContexts)}`);
  }

  // Return result.
  return {
    protectedHeader: header as ICTHeader,
    payload: payload as ICTPayload,
  };
}
