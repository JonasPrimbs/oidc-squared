export abstract class NonceGenerator {

  /**
   * Generates a new nonce.
   * @returns The generated nonce.
   */
  abstract generate(): string;
}
