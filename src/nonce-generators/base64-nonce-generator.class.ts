import * as crypto from 'crypto';

import { NonceGenerator } from './nonce-generator.class';

export class Base64NonceGenerator extends NonceGenerator {

  /**
   * Constructs a new Nonce Generator which generates random bytes and encodes them Base64.
   * @param length The number of random bytes to generate.
   */
  constructor(public readonly length: number) {
    if (!Number.isInteger(length)) {
      throw 'Length must be a an integer value!';
    }
    if (length <= 0) {
      throw `Length must be a positive number! Provided length: ${length}`;
    }

    super();
  }

  /**
   * Generates the configured number of random bytes and encodes them Base64.
   * @returns The generated nonce.
   */
  generate(): string {
    const data = crypto.getRandomValues<Uint8Array>(new Uint8Array(this.length));
    let str = '';
    for (let i = 0; i < data.length; i++) {
      str += String.fromCharCode(data[i]);
    }
    return (typeof window !== 'undefined') ? window.btoa(str) : Buffer.from(str).toString('base64');
  }
}
