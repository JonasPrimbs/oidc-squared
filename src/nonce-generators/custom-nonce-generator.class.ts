import { NonceGenerator } from './nonce-generator.class';

export class CustomNonceGenerator extends NonceGenerator {

  /**
   * Constructs a new Custom Nonce Generator.
   * @param generator The generator function.
   */
  constructor(private readonly generator: () => string) {
    super();
  }

  /**
   * Generates a new nonce using the provided generator function.
   * @returns The generated nonce.
   */
  generate(): string {
    return this.generator();
  }
}
