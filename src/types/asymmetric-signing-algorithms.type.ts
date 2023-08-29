export type AsymmetricSigningAlgorithms = 'ES256' | 'ES384' | 'ES512' | 'RS256' | 'RS384' | 'RS512' | 'PS256' | 'PS384' | 'PS512';

export const AVAILABLE_ASYMMETRIC_SIGNING_ALGORITHMS = [
  // Elliptic curve:
  'ES256',
  'ES384',
  'ES512',
  // RSA:
  'RS256',
  'RS384',
  'RS512',
  // RSA-PSSA:
  'PS256',
  'PS384',
  'PS512',
];
