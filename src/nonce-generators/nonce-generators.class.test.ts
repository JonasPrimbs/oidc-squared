import { Base64NonceGenerator } from './base64-nonce-generator.class';
import { CustomNonceGenerator } from './custom-nonce-generator.class';
import { NonceGenerators } from './nonce-generators.class';
import { UuidNonceGenerator } from './uuid-nonce-generator.class';

test('NonceGenerators.base64 returns a valid Base64NonceGenerator', () => {
  // Verify that NonceGneerators.base64() returns a Base64NonceGenerator instance.
  expect(NonceGenerators.base64(16)).toBeInstanceOf(Base64NonceGenerator);

  // Verify that the returned Base64 Nonce Generator has the correct length.
  expect(NonceGenerators.base64(16).length).toBe(16);

  // Verify that the returned Base64 Nonce Generator generates a valid Base64 string.
  expect(NonceGenerators.base64(16).generate()).toMatch(new RegExp('^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'));
});

test('NonceGenerators.custom returns a valid CustomNonceGenerator', () => {
  // Verify that NonceGneerators.custom() returns a CustomNonceGenerator instance.
  expect(NonceGenerators.custom(() => 'test')).toBeInstanceOf(CustomNonceGenerator);

  // Verify that the returned Custom Nonce Generator generates the correct value.
  expect(NonceGenerators.custom(() => 'test').generate()).toBe('test');
});

test('NonceGenerators.uuid returns a valid UuidNonceGenerator', () => {
  // Verify that NonceGneerators.uuid() returns a UuidNonceGenerator instance.
  expect(NonceGenerators.uuid()).toBeInstanceOf(UuidNonceGenerator);

  // Verify that the returned UUID Nonce Generator generates a valid UUID string.
  expect(NonceGenerators.uuid().generate()).toMatch(new RegExp('^[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$'));
});
