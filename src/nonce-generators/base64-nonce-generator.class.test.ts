import { Base64NonceGenerator } from './base64-nonce-generator.class';

test('creates Base64 Nonce Generator of length 16', () => {
  // Verify that Base64 Nonce Generator does not throw an error on generation.
  expect(() => new Base64NonceGenerator(16)).not.toThrow();

  // Verify that UUID Nonce Generator generates a correct instance of a CustomNonceGenerator.
  expect(new Base64NonceGenerator(16)).toBeInstanceOf(Base64NonceGenerator);

  // Verify that length is correct.
  expect(new Base64NonceGenerator(16).length).toBe(16);
});

test('creates Base64 Nonce Generator of invalid length', () => {
  // Verify that Base64 Nonce Generator throws an error on creation with length = 0.
  expect(() => new Base64NonceGenerator(0)).toThrow();

  // Verify that Base64 Nonce Generator throws an error on creation with length = -1.
  expect(() => new Base64NonceGenerator(-1)).toThrow();
  
  // Verify that Base64 Nonce Generator throws an error on creation with length = infinity.
  expect(() => new Base64NonceGenerator(Infinity)).toThrow();

  // Verify that Base64 Nonce Generator throws an error on creation with length = -infinity.
  expect(() => new Base64NonceGenerator(Number.NEGATIVE_INFINITY)).toThrow();

  // Verify that Base64 Nonce Generator throws an error on creation with length = NaN.
  expect(() => new Base64NonceGenerator(NaN)).toThrow();

  // Verify that Base64 Nonce Generator throws an error on creation with length = 0.5.
  expect(() => new Base64NonceGenerator(0.5)).toThrow();
});

test('generates Base64 nonce of length 1', () => {
  const nonceGenerator = new Base64NonceGenerator(1);

  // Verify that nonce can be generated.
  expect(() => nonceGenerator.generate()).not.toThrow();

  // Verify that nonce is a string.
  expect(typeof nonceGenerator.generate()).toBe('string');

  // Verify that nonce is a base64 string.
  expect(nonceGenerator.generate()).toMatch(new RegExp('^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'));
});

test('generates Base64 nonce of length 2', () => {
  const nonceGenerator = new Base64NonceGenerator(2);

  // Verify that nonce can be generated.
  expect(() => nonceGenerator.generate()).not.toThrow();

  // Verify that nonce is a string.
  expect(typeof nonceGenerator.generate()).toBe('string');

  // Verify that nonce is a base64 string.
  expect(nonceGenerator.generate()).toMatch(new RegExp('^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'));
});

test('generates Base64 nonce of length 3', () => {
  const nonceGenerator = new Base64NonceGenerator(3);

  // Verify that nonce can be generated.
  expect(() => nonceGenerator.generate()).not.toThrow();

  // Verify that nonce is a string.
  expect(typeof nonceGenerator.generate()).toBe('string');

  // Verify that nonce is a base64 string.
  expect(nonceGenerator.generate()).toMatch(new RegExp('^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'));
});
