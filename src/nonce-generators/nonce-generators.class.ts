import { Base64NonceGenerator } from './base64-nonce-generator.class';
import { CustomNonceGenerator } from './custom-nonce-generator.class';
import { UuidNonceGenerator } from './uuid-nonce-generator.class';

export class NonceGenerators {

  /**
   * Creates a new Base64 Nonce Generator.
   * @param length Number of random bytes that should be generated.
   * @returns The new Base64 Nonce Generator.
   */
  static base64(length: number): Base64NonceGenerator {
    return new Base64NonceGenerator(length);
  }

  /**
   * Creates a new Custom Nonce Generator.
   * @param generator Generator function for the custom nonce generator.
   * @returns The new Custom Nonce Generator.
   */
  static custom(generator: () => string): CustomNonceGenerator {
    return new CustomNonceGenerator(generator);
  }

  /**
   * Creates a new UUID Nonce Generator.
   * @returns The new UUID Nonce Generator.
   */
  static uuid(): UuidNonceGenerator {
    return new UuidNonceGenerator();
  } 
}
