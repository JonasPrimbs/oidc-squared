import * as crypto from 'crypto';

import { NonceGenerator } from './nonce-generator.class';

export class UuidNonceGenerator extends NonceGenerator {

  /**
   * Generates a new random UUID as nonce.
   * @returns The generated nonce.
   */
  generate(): string {
    return crypto.randomUUID();
  }
}
