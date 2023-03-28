import { CustomNonceGenerator } from './custom-nonce-generator.class';

test('creates Custom Nonce Generator', () => {
  // Verify that Custom Nonce Generator does not throw an error on generation.
  expect(() => new CustomNonceGenerator(() => 'test')).not.toThrow();

  // Verify that UUID Nonce Generator generates a correct instance of a CustomNonceGenerator.
  expect(new CustomNonceGenerator(() => 'test')).toBeInstanceOf(CustomNonceGenerator);
});

test('Custom Nonce Generator generates valid custom nonces', () => {
  // Verify that UUID Nonce Generator does not throw an error on generation.
  expect(() => new CustomNonceGenerator(() => 'test').generate()).not.toThrow();

  // Verify that the generator function generates a valid UUID.
  expect(new CustomNonceGenerator(() => 'test').generate()).toBe('test');
});

test('creates Custom Nonce Generator of throwing generator function', () => {
  // Verify that Custom Nonce Generator whose generator throws an error, really throws an error.
  expect(() => new CustomNonceGenerator(() => {
    throw new Error('error');
  }).generate()).toThrow();
});
