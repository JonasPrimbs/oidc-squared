import { UuidNonceGenerator } from './uuid-nonce-generator.class';

test('creates UUID Nonce Generator', () => {
  // Verify that UUID Nonce Generator does not throw an error on generation.
  expect(() => new UuidNonceGenerator()).not.toThrow();

  // Verify that UUID Nonce Generator generates a correct instance of a UuidNonceGenerator.
  expect(new UuidNonceGenerator()).toBeInstanceOf(UuidNonceGenerator);
});

test('UUID Nonce Generator generates valid UUIDs', () => {
  // Verify that UUID Nonce Generator does not throw an error on generation.
  expect(() => new UuidNonceGenerator().generate()).not.toThrow();

  // Verify that the generator function generates a valid UUID.
  expect(new UuidNonceGenerator().generate()).toMatch(new RegExp('^[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$'));
});
