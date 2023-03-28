import * as crypto from 'crypto';

import { IctRequestToken } from './ict-request-token.class';
import { IrtClaimsSpecification } from './irt-claims-specification.interface';

test('creates ICT Request Token', () => {
  // Do not throw an error when creating an ICT Request Token.
  expect(() => new IctRequestToken).not.toThrow();

  // Create an instance.
  expect(new IctRequestToken()).toBeInstanceOf(IctRequestToken);
});

test('gets no public key from an empty ICT Request Token', async () => {
  // Create a new IRT.
  const irt = new IctRequestToken();

  // Verify that hasPublicKey method does not throw.
  expect(() => irt.hasPublicKey()).not.toThrow();

  // Verify that no public key is set at beginning.
  expect(irt.hasPublicKey()).toBe(false);

  // Verify that getPublicKey method does not throw.
  expect(() => irt.getPublicKey()).not.toThrow();

  // Verify that an undefined public key is returned.
  expect(irt.getPublicKey()).toBe(undefined);

  // Export keys.
  const [
    jwkKey,
    pkcs8Key,
    rawKey,
    spkiKey,
  ] = await Promise.all([
    irt.exportPublicKey('jwk'),
    irt.exportPublicKey('pkcs8'),
    irt.exportPublicKey('raw'),
    irt.exportPublicKey('spki'),
  ]);

  // Verify that an undefined public key is exported.
  expect(jwkKey).toBe(undefined);
  expect(pkcs8Key).toBe(undefined);
  expect(rawKey).toBe(undefined);
  expect(spkiKey).toBe(undefined);
});

test('sets an elliptic curve key to an empty ICT Request Token', async () => {
  // Create keys.
  const [
    ec256KeyPair,
    ec384KeyPair,
    ec512KeyPair,
    ec256KeyPairNoExt,
    ec384KeyPairNoExt,
    ec512KeyPairNoExt,
    rsaEncKeyPair,
    rs256KeyPair,
    rs384KeyPair,
    rs512KeyPair,
    hs512Key,
    ps256KeyPair,
    ps384KeyPair,
    ps512KeyPair,
  ] = await Promise.all([
    crypto.subtle.generateKey({
      name: 'ECDSA', namedCurve: 'P-256', 
    }, true, ['sign', 'verify']),
    crypto.subtle.generateKey({
      name: 'ECDSA', namedCurve: 'P-384', 
    }, true, ['sign', 'verify']),
    crypto.subtle.generateKey({
      name: 'ECDSA', namedCurve: 'P-521', 
    }, true, ['sign', 'verify']),
    crypto.subtle.generateKey({
      name: 'ECDSA', namedCurve: 'P-256', 
    }, false, ['sign', 'verify']),
    crypto.subtle.generateKey({
      name: 'ECDSA', namedCurve: 'P-384', 
    }, false, ['sign', 'verify']),
    crypto.subtle.generateKey({
      name: 'ECDSA', namedCurve: 'P-521', 
    }, false, ['sign', 'verify']),
    crypto.subtle.generateKey({
      name: 'RSA-OAEP', modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256',
    }, false, ['encrypt', 'decrypt']),
    crypto.subtle.generateKey({
      name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256',
    }, false, ['sign', 'verify']),
    crypto.subtle.generateKey({
      name: 'RSASSA-PKCS1-v1_5', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-384',
    }, false, ['sign', 'verify']),
    crypto.subtle.generateKey({
      name: 'RSASSA-PKCS1-v1_5', modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-512',
    }, false, ['sign', 'verify']),
    crypto.subtle.generateKey({
      name: 'HMAC', hash: {
        name: 'SHA-512', 
      },
    }, false, ['sign', 'verify']),
    crypto.subtle.generateKey({
      name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256',
    }, false, ['sign', 'verify']),
    crypto.subtle.generateKey({
      name: 'RSA-PSS', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-384',
    }, false, ['sign', 'verify']),
    crypto.subtle.generateKey({
      name: 'RSA-PSS', modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-512',
    }, false, ['sign', 'verify']),
  ]);

  // Verify that setting a public key of a non-extractable key pair does not throw.
  expect(() => new IctRequestToken().setPublicKey(ec256KeyPairNoExt.publicKey)).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(ec384KeyPairNoExt.publicKey)).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(ec512KeyPairNoExt.publicKey)).not.toThrow();

  // Verify that setting an encryption or symmetric key does throw an error.
  expect(() => new IctRequestToken().setPublicKey(hs512Key)).toThrow();
  expect(() => new IctRequestToken().setPublicKey(rsaEncKeyPair.publicKey)).toThrow();
  expect(() => new IctRequestToken().setPublicKey(rsaEncKeyPair.privateKey)).toThrow();

  // Verify that setting a private key does throw an error.
  expect(() => new IctRequestToken().setPublicKey(ec256KeyPair.privateKey)).toThrow();
  expect(() => new IctRequestToken().setPublicKey(ec384KeyPair.privateKey)).toThrow();
  expect(() => new IctRequestToken().setPublicKey(ec512KeyPair.privateKey)).toThrow();

  // Verify that setting a sufficient public key does not throw an error.
  expect(() => new IctRequestToken().setPublicKey(ec256KeyPair.publicKey)).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(ec384KeyPair.publicKey)).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(ec512KeyPair.publicKey)).not.toThrow();

  // Verify that setting a public key and checking whether a public key is set does not throw an error.
  expect(() => new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).hasPublicKey()).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(ec384KeyPair.publicKey).hasPublicKey()).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(ec512KeyPair.publicKey).hasPublicKey()).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(rs256KeyPair.publicKey).hasPublicKey()).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(rs384KeyPair.publicKey).hasPublicKey()).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(rs512KeyPair.publicKey).hasPublicKey()).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(ps256KeyPair.publicKey).hasPublicKey()).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(ps384KeyPair.publicKey).hasPublicKey()).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(ps512KeyPair.publicKey).hasPublicKey()).not.toThrow();

  // Verify that setting a public key and exporting the public key does not throw an error.
  expect(() => new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).exportPublicKey('jwk')).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(ec384KeyPair.publicKey).exportPublicKey('jwk')).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(ec512KeyPair.publicKey).exportPublicKey('jwk')).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).exportPublicKey('raw')).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(ec384KeyPair.publicKey).exportPublicKey('raw')).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(ec512KeyPair.publicKey).exportPublicKey('raw')).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).exportPublicKey('spki')).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(ec384KeyPair.publicKey).exportPublicKey('spki')).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(ec512KeyPair.publicKey).exportPublicKey('spki')).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(rs256KeyPair.publicKey).exportPublicKey('jwk')).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(rs384KeyPair.publicKey).exportPublicKey('jwk')).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(rs512KeyPair.publicKey).exportPublicKey('jwk')).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(rs256KeyPair.publicKey).exportPublicKey('spki')).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(rs384KeyPair.publicKey).exportPublicKey('spki')).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(rs512KeyPair.publicKey).exportPublicKey('spki')).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(ps256KeyPair.publicKey).exportPublicKey('jwk')).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(ps384KeyPair.publicKey).exportPublicKey('jwk')).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(ps512KeyPair.publicKey).exportPublicKey('jwk')).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(ps256KeyPair.publicKey).exportPublicKey('spki')).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(ps384KeyPair.publicKey).exportPublicKey('spki')).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(ps512KeyPair.publicKey).exportPublicKey('spki')).not.toThrow();

  // Verify that setting a public key and checking whether a public key is set returns true.
  expect(new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).hasPublicKey()).toBe(true);
  expect(new IctRequestToken().setPublicKey(ec384KeyPair.publicKey).hasPublicKey()).toBe(true);
  expect(new IctRequestToken().setPublicKey(ec512KeyPair.publicKey).hasPublicKey()).toBe(true);
  expect(new IctRequestToken().setPublicKey(rs256KeyPair.publicKey).hasPublicKey()).toBe(true);
  expect(new IctRequestToken().setPublicKey(rs384KeyPair.publicKey).hasPublicKey()).toBe(true);
  expect(new IctRequestToken().setPublicKey(rs512KeyPair.publicKey).hasPublicKey()).toBe(true);
  expect(new IctRequestToken().setPublicKey(ps256KeyPair.publicKey).hasPublicKey()).toBe(true);
  expect(new IctRequestToken().setPublicKey(ps384KeyPair.publicKey).hasPublicKey()).toBe(true);
  expect(new IctRequestToken().setPublicKey(ps512KeyPair.publicKey).hasPublicKey()).toBe(true);

  // Verify that no public key is set at beginning.
  expect(new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).getPublicKey()).toBeInstanceOf(crypto.webcrypto.CryptoKey);
  expect(new IctRequestToken().setPublicKey(ec384KeyPair.publicKey).getPublicKey()).toBeInstanceOf(crypto.webcrypto.CryptoKey);
  expect(new IctRequestToken().setPublicKey(ec512KeyPair.publicKey).getPublicKey()).toBeInstanceOf(crypto.webcrypto.CryptoKey);
  expect(new IctRequestToken().setPublicKey(rs256KeyPair.publicKey).getPublicKey()).toBeInstanceOf(crypto.webcrypto.CryptoKey);
  expect(new IctRequestToken().setPublicKey(rs384KeyPair.publicKey).getPublicKey()).toBeInstanceOf(crypto.webcrypto.CryptoKey);
  expect(new IctRequestToken().setPublicKey(rs512KeyPair.publicKey).getPublicKey()).toBeInstanceOf(crypto.webcrypto.CryptoKey);
  expect(new IctRequestToken().setPublicKey(ps256KeyPair.publicKey).getPublicKey()).toBeInstanceOf(crypto.webcrypto.CryptoKey);
  expect(new IctRequestToken().setPublicKey(ps384KeyPair.publicKey).getPublicKey()).toBeInstanceOf(crypto.webcrypto.CryptoKey);
  expect(new IctRequestToken().setPublicKey(ps512KeyPair.publicKey).getPublicKey()).toBeInstanceOf(crypto.webcrypto.CryptoKey);

  // Export keys.
  const [
    raw256,
    raw384,
    raw512,
    spki256,
    spki384,
    spki512,
  ] = await Promise.all([
    new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).exportPublicKey('raw'),
    new IctRequestToken().setPublicKey(ec384KeyPair.publicKey).exportPublicKey('raw'),
    new IctRequestToken().setPublicKey(ec512KeyPair.publicKey).exportPublicKey('raw'),
    new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).exportPublicKey('spki'),
    new IctRequestToken().setPublicKey(ec384KeyPair.publicKey).exportPublicKey('spki'),
    new IctRequestToken().setPublicKey(ec512KeyPair.publicKey).exportPublicKey('spki'),
  ]);

  expect(raw256).toBeInstanceOf(ArrayBuffer);
  expect(raw384).toBeInstanceOf(ArrayBuffer);
  expect(raw512).toBeInstanceOf(ArrayBuffer);
  expect(spki256).toBeInstanceOf(ArrayBuffer);
  expect(spki384).toBeInstanceOf(ArrayBuffer);
  expect(spki512).toBeInstanceOf(ArrayBuffer);
});

test('sets an RSA key to an empty ICT Request Token', async () => {
  // Create keys.
  const [
    rs256KeyPair,
    rs384KeyPair,
    rs512KeyPair,
    rs256KeyPairNoExt,
    rs384KeyPairNoExt,
    rs512KeyPairNoExt,
  ] = await Promise.all([
    crypto.subtle.generateKey({
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: {
        name: 'SHA-256',
      },
    }, true, ['sign', 'verify']),
    crypto.subtle.generateKey({
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: {
        name: 'SHA-384',
      },
    }, true, ['sign', 'verify']),
    crypto.subtle.generateKey({
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: {
        name: 'SHA-512',
      },
    }, true, ['sign', 'verify']),
    crypto.subtle.generateKey({
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: {
        name: 'SHA-256',
      },
    }, false, ['sign', 'verify']),
    crypto.subtle.generateKey({
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: {
        name: 'SHA-384',
      },
    }, false, ['sign', 'verify']),
    crypto.subtle.generateKey({
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: {
        name: 'SHA-512',
      },
    }, false, ['sign', 'verify']),
  ]);

  // Verify that setting a public key of a non-extractable key pair does not throw.
  expect(() => new IctRequestToken().setPublicKey(rs256KeyPairNoExt.publicKey)).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(rs384KeyPairNoExt.publicKey)).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(rs512KeyPairNoExt.publicKey)).not.toThrow();

  // Verify that setting a private key does throw an error.
  expect(() => new IctRequestToken().setPublicKey(rs256KeyPair.privateKey)).toThrow();
  expect(() => new IctRequestToken().setPublicKey(rs384KeyPair.privateKey)).toThrow();
  expect(() => new IctRequestToken().setPublicKey(rs512KeyPair.privateKey)).toThrow();

  // Verify that setting a sufficient public key does not throw an error.
  expect(() => new IctRequestToken().setPublicKey(rs256KeyPair.publicKey)).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(rs384KeyPair.publicKey)).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(rs512KeyPair.publicKey)).not.toThrow();

  // Verify that setting a public key and checking whether a public key is set does not throw an error.
  expect(() => new IctRequestToken().setPublicKey(rs256KeyPair.publicKey).hasPublicKey()).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(rs384KeyPair.publicKey).hasPublicKey()).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(rs512KeyPair.publicKey).hasPublicKey()).not.toThrow();

  // Verify that setting a public key and exporting the public key does not throw an error.
  expect(() => new IctRequestToken().setPublicKey(rs256KeyPair.publicKey).exportPublicKey('jwk')).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(rs384KeyPair.publicKey).exportPublicKey('jwk')).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(rs512KeyPair.publicKey).exportPublicKey('jwk')).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(rs256KeyPair.publicKey).exportPublicKey('spki')).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(rs384KeyPair.publicKey).exportPublicKey('spki')).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(rs512KeyPair.publicKey).exportPublicKey('spki')).not.toThrow();

  // Verify that setting a public key and checking whether a public key is set returns true.
  expect(new IctRequestToken().setPublicKey(rs256KeyPair.publicKey).hasPublicKey()).toBe(true);
  expect(new IctRequestToken().setPublicKey(rs384KeyPair.publicKey).hasPublicKey()).toBe(true);
  expect(new IctRequestToken().setPublicKey(rs512KeyPair.publicKey).hasPublicKey()).toBe(true);

  // Verify that no public key is set at beginning.
  expect(new IctRequestToken().setPublicKey(rs256KeyPair.publicKey).getPublicKey()).toBeInstanceOf(crypto.webcrypto.CryptoKey);
  expect(new IctRequestToken().setPublicKey(rs384KeyPair.publicKey).getPublicKey()).toBeInstanceOf(crypto.webcrypto.CryptoKey);
  expect(new IctRequestToken().setPublicKey(rs512KeyPair.publicKey).getPublicKey()).toBeInstanceOf(crypto.webcrypto.CryptoKey);

  // Export keys.
  const [
    spki256,
    spki384,
    spki512,
  ] = await Promise.all([
    new IctRequestToken().setPublicKey(rs256KeyPair.publicKey).exportPublicKey('spki'),
    new IctRequestToken().setPublicKey(rs384KeyPair.publicKey).exportPublicKey('spki'),
    new IctRequestToken().setPublicKey(rs512KeyPair.publicKey).exportPublicKey('spki'),
  ]);

  expect(spki256).toBeInstanceOf(ArrayBuffer);
  expect(spki384).toBeInstanceOf(ArrayBuffer);
  expect(spki512).toBeInstanceOf(ArrayBuffer);
});

test('gets audience from an empty ICT Request Token', () => {
  expect(() => new IctRequestToken().hasAudience()).not.toThrow();
  expect(new IctRequestToken().hasAudience()).toBe(false);

  expect(() => new IctRequestToken().getAudience()).not.toThrow();
  expect(new IctRequestToken().getAudience()).toBeUndefined();

  expect(new IctRequestToken().containsAudience('')).toBe(false);
});

test('sets audience to an empty ICT Request Token', () => {
  expect(() => new IctRequestToken().setAudience('test')).not.toThrow();
  expect(() => new IctRequestToken().setAudience(['test'])).not.toThrow();
  expect(() => new IctRequestToken().setAudience(['test1', 'test2'])).not.toThrow();
  expect(() => new IctRequestToken().setAudience(['test', 'test'])).not.toThrow();
  expect(() => new IctRequestToken().setAudience([])).not.toThrow();
  expect(() => new IctRequestToken().setAudience([''])).not.toThrow();
  expect(() => new IctRequestToken().setAudience(['', ''])).not.toThrow();
  expect(() => new IctRequestToken().setAudience(':')).toThrow();
  expect(() => new IctRequestToken().setAudience([':'])).toThrow();
  expect(() => new IctRequestToken().setAudience(['test', ':'])).toThrow();
  expect(() => new IctRequestToken().setAudience('urn:test')).not.toThrow();
  expect(() => new IctRequestToken().setAudience(['urn:test', 'https://test.example.org'])).not.toThrow();

  expect(new IctRequestToken().setAudience('test')).toBeInstanceOf(IctRequestToken);
  expect(new IctRequestToken().setAudience(['test'])).toBeInstanceOf(IctRequestToken);
  expect(new IctRequestToken().setAudience(['test1', 'test2'])).toBeInstanceOf(IctRequestToken);
  expect(new IctRequestToken().setAudience(['test', 'test'])).toBeInstanceOf(IctRequestToken);
  expect(new IctRequestToken().setAudience(['test1', ''])).toBeInstanceOf(IctRequestToken);
  expect(new IctRequestToken().setAudience('urn:test')).toBeInstanceOf(IctRequestToken);
  expect(new IctRequestToken().setAudience(['urn:test', 'https://test.example.org'])).toBeInstanceOf(IctRequestToken);
  expect(new IctRequestToken().setAudience('')).toBeInstanceOf(IctRequestToken);
  expect(new IctRequestToken().setAudience([''])).toBeInstanceOf(IctRequestToken);
  expect(new IctRequestToken().setAudience(['', ''])).toBeInstanceOf(IctRequestToken);
  expect(new IctRequestToken().setAudience([])).toBeInstanceOf(IctRequestToken);

  expect(new IctRequestToken().setAudience('test').hasAudience()).toBe(true);
  expect(new IctRequestToken().setAudience(['test']).hasAudience()).toBe(true);
  expect(new IctRequestToken().setAudience(['test1', 'test2']).hasAudience()).toBe(true);
  expect(new IctRequestToken().setAudience(['test', 'test']).hasAudience()).toBe(true);
  expect(new IctRequestToken().setAudience(['test1', '']).hasAudience()).toBe(true);
  expect(new IctRequestToken().setAudience('urn:test').hasAudience()).toBe(true);
  expect(new IctRequestToken().setAudience(['urn:test', 'https://test.example.org']).hasAudience()).toBe(true);

  expect(new IctRequestToken().setAudience('').hasAudience()).toBe(false);
  expect(new IctRequestToken().setAudience(['']).hasAudience()).toBe(false);
  expect(new IctRequestToken().setAudience(['', '']).hasAudience()).toBe(false);
  expect(new IctRequestToken().setAudience([]).hasAudience()).toBe(false);

  expect(new IctRequestToken().setAudience('test').getAudience()).toEqual(['test']);
  expect(new IctRequestToken().setAudience(['test']).getAudience()).toEqual(['test']);
  expect(new IctRequestToken().setAudience(['test1', 'test2']).getAudience()).toEqual(['test1', 'test2']);
  expect(new IctRequestToken().setAudience(['test', 'test']).getAudience()).toEqual(['test']);
  expect(new IctRequestToken().setAudience(['test1', '']).getAudience()).toEqual(['test1']);
  expect(new IctRequestToken().setAudience('urn:test').getAudience()).toEqual(['urn:test']);
  expect(new IctRequestToken().setAudience(['urn:test', 'https://test.example.org']).getAudience()).toEqual(['urn:test', 'https://test.example.org']);

  expect(new IctRequestToken().setAudience('').getAudience()).toBeUndefined();
  expect(new IctRequestToken().setAudience(['']).getAudience()).toBeUndefined();
  expect(new IctRequestToken().setAudience(['', '']).getAudience()).toBeUndefined();
  expect(new IctRequestToken().setAudience([]).getAudience()).toBeUndefined();

  expect(new IctRequestToken().setAudience('test').containsAudience('test')).toBe(true);
  expect(new IctRequestToken().setAudience(['test']).containsAudience('test')).toBe(true);
  expect(new IctRequestToken().setAudience(['test1', 'test2']).containsAudience('test2')).toBe(true);
  expect(new IctRequestToken().setAudience(['test1', '']).containsAudience('test1')).toBe(true);
  expect(new IctRequestToken().setAudience('urn:test').containsAudience('urn:test')).toBe(true);
  expect(new IctRequestToken().setAudience(['urn:test', 'https://test.example.org']).containsAudience('urn:test')).toBe(true);

  expect(new IctRequestToken().setAudience(['test1', '']).containsAudience('')).toBe(false);
  expect(new IctRequestToken().setAudience('').containsAudience('')).toBe(false);
  expect(new IctRequestToken().setAudience(['']).containsAudience('')).toBe(false);
  expect(new IctRequestToken().setAudience(['', '']).containsAudience('')).toBe(false);
  expect(new IctRequestToken().setAudience([]).containsAudience('')).toBe(false);
});

test('gets subject from an empty ICT Request Token', () => {
  expect(() => new IctRequestToken().hasSubject()).not.toThrow();
  expect(new IctRequestToken().hasSubject()).toBe(false);

  expect(() => new IctRequestToken().getSubject()).not.toThrow();
  expect(new IctRequestToken().getSubject()).toBeUndefined();
});

test('sets subject to an empty ICT Request Token', () => {
  expect(() => new IctRequestToken().setSubject('test')).not.toThrow();
  expect(() => new IctRequestToken().setSubject(':')).toThrow();
  expect(() => new IctRequestToken().setSubject('urn:test')).not.toThrow();

  expect(new IctRequestToken().setSubject('test')).toBeInstanceOf(IctRequestToken);
  expect(new IctRequestToken().setSubject('urn:test')).toBeInstanceOf(IctRequestToken);
  expect(new IctRequestToken().setSubject('')).toBeInstanceOf(IctRequestToken);

  expect(new IctRequestToken().setSubject('test').hasSubject()).toBe(true);
  expect(new IctRequestToken().setSubject('urn:test').hasSubject()).toBe(true);

  expect(new IctRequestToken().setSubject('').hasSubject()).toBe(false);

  expect(new IctRequestToken().setSubject('test').getSubject()).toBe('test');
  expect(new IctRequestToken().setSubject('urn:test').getSubject()).toBe('urn:test');

  expect(new IctRequestToken().setSubject('').getSubject()).toBeUndefined();
});

test('gets issuer from an empty ICT Request Token', () => {
  expect(() => new IctRequestToken().hasIssuer()).not.toThrow();
  expect(new IctRequestToken().hasIssuer()).toBe(false);

  expect(() => new IctRequestToken().getIssuer()).not.toThrow();
  expect(new IctRequestToken().getIssuer()).toBeUndefined();
});

test('sets issuer to an empty ICT Request Token', () => {
  expect(() => new IctRequestToken().setIssuer('test')).not.toThrow();
  expect(() => new IctRequestToken().setIssuer(':')).toThrow();
  expect(() => new IctRequestToken().setIssuer('urn:test')).not.toThrow();

  expect(new IctRequestToken().setIssuer('test')).toBeInstanceOf(IctRequestToken);
  expect(new IctRequestToken().setIssuer('urn:test')).toBeInstanceOf(IctRequestToken);
  expect(new IctRequestToken().setIssuer('')).toBeInstanceOf(IctRequestToken);

  expect(new IctRequestToken().setIssuer('test').hasIssuer()).toBe(true);
  expect(new IctRequestToken().setIssuer('urn:test').hasIssuer()).toBe(true);

  expect(new IctRequestToken().setIssuer('').hasIssuer()).toBe(false);

  expect(new IctRequestToken().setIssuer('test').getIssuer()).toBe('test');
  expect(new IctRequestToken().setIssuer('urn:test').getIssuer()).toBe('urn:test');

  expect(new IctRequestToken().setIssuer('').getIssuer()).toBeUndefined();
});

test('gets JWT Token ID from an empty ICT Request Token', () => {
  expect(() => new IctRequestToken().hasJti()).not.toThrow();
  expect(new IctRequestToken().hasJti()).toBe(false);

  expect(() => new IctRequestToken().getJti()).not.toThrow();
  expect(new IctRequestToken().getJti()).toBeUndefined();
});

test('sets JWT Token ID to an empty ICT Request Token', () => {
  expect(() => new IctRequestToken().setJti()).not.toThrow();
  expect(() => new IctRequestToken().setJti('test')).not.toThrow();
  expect(() => new IctRequestToken().setJti('urn:test')).not.toThrow();
  expect(() => new IctRequestToken().setJti('')).toThrow();

  expect(new IctRequestToken().setJti()).toBeInstanceOf(IctRequestToken);
  expect(new IctRequestToken().setJti('test')).toBeInstanceOf(IctRequestToken);
  expect(new IctRequestToken().setJti('urn:test')).toBeInstanceOf(IctRequestToken);

  expect(new IctRequestToken().setJti().hasJti()).toBe(true);
  expect(new IctRequestToken().setJti('test').hasJti()).toBe(true);
  expect(new IctRequestToken().setJti('urn:test').hasJti()).toBe(true);

  expect(new IctRequestToken().setJti().getJti()).toMatch(new RegExp('^[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$'));
  expect(new IctRequestToken().setJti('test').getJti()).toBe('test');
  expect(new IctRequestToken().setJti('urn:test').getJti()).toBe('urn:test');
});

test('gets nonce from an empty ICT Request Token', () => {
  expect(() => new IctRequestToken().hasNonce()).not.toThrow();
  expect(new IctRequestToken().hasNonce()).toBe(false);

  expect(() => new IctRequestToken().getNonce()).not.toThrow();
  expect(new IctRequestToken().getNonce()).toBeUndefined();
});

test('sets nonce to an empty ICT Request Token', () => {
  expect(() => new IctRequestToken().setNonce()).not.toThrow();
  expect(() => new IctRequestToken().setNonce('test')).not.toThrow();
  expect(() => new IctRequestToken().setNonce('urn:test')).not.toThrow();
  expect(() => new IctRequestToken().setNonce('')).toThrow();

  expect(new IctRequestToken().setNonce()).toBeInstanceOf(IctRequestToken);
  expect(new IctRequestToken().setNonce('test')).toBeInstanceOf(IctRequestToken);
  expect(new IctRequestToken().setNonce('urn:test')).toBeInstanceOf(IctRequestToken);

  expect(new IctRequestToken().setNonce().hasNonce()).toBe(true);
  expect(new IctRequestToken().setNonce('test').hasNonce()).toBe(true);
  expect(new IctRequestToken().setNonce('urn:test').hasNonce()).toBe(true);
  
  expect(new IctRequestToken().setNonce().getNonce()).toMatch(new RegExp('^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'));
  expect(new IctRequestToken().setNonce('test').getNonce()).toBe('test');
  expect(new IctRequestToken().setNonce('urn:test').getNonce()).toBe('urn:test');
});

test('gets issued at from an empty ICT Request Token', () => {
  expect(() => new IctRequestToken().hasIssuedAt()).not.toThrow();
  expect(new IctRequestToken().hasIssuedAt()).toBe(false);

  expect(() => new IctRequestToken().getIssuedAt()).not.toThrow();
  expect(new IctRequestToken().getIssuedAt()).toBeUndefined();

  expect(() => new IctRequestToken().getIssuedAtDate()).not.toThrow();
  expect(new IctRequestToken().getIssuedAtDate()).toBeUndefined();
});

test('sets issued at to an empty ICT Request Token', () => {
  expect(() => new IctRequestToken().setIssuedAt()).not.toThrow();
  expect(() => new IctRequestToken().setIssuedAt(1679612400)).not.toThrow();
  expect(() => new IctRequestToken().setIssuedAt(new Date('2023-03-24 00:00:00'))).not.toThrow();

  expect(() => new IctRequestToken().setIssuedAt(-1)).toThrow();
  expect(() => new IctRequestToken().setIssuedAt(Infinity)).toThrow();
  expect(() => new IctRequestToken().setIssuedAt(Number.NEGATIVE_INFINITY)).toThrow();
  expect(() => new IctRequestToken().setIssuedAt(Number.NaN)).toThrow();

  expect(new IctRequestToken().setIssuedAt()).toBeInstanceOf(IctRequestToken);
  expect(new IctRequestToken().setIssuedAt(1679612400)).toBeInstanceOf(IctRequestToken);
  expect(new IctRequestToken().setIssuedAt(new Date('2023-03-24 00:00:00'))).toBeInstanceOf(IctRequestToken);

  expect(new IctRequestToken().setIssuedAt().hasIssuedAt()).toBe(true);
  expect(new IctRequestToken().setIssuedAt(1679612400).hasIssuedAt()).toBe(true);
  expect(new IctRequestToken().setIssuedAt(new Date('2023-03-24 00:00:00')).hasIssuedAt()).toBe(true);

  expect(new IctRequestToken().setIssuedAt().getIssuedAt()).toBeLessThanOrEqual(Math.ceil(Date.now() / 1000));
  expect(new IctRequestToken().setIssuedAt(1679612400).getIssuedAt()).toBe(1679612400);
  expect(new IctRequestToken().setIssuedAt(new Date('2023-03-24 00:00:00')).getIssuedAt()).toBe(1679612400);

  expect(new IctRequestToken().setIssuedAt(1679612400).getIssuedAtDate()).toEqual(new Date('2023-03-24 00:00:00'));
  expect(new IctRequestToken().setIssuedAt(new Date('2023-03-24 00:00:00')).getIssuedAtDate()).toEqual(new Date('2023-03-24 00:00:00'));
});

test('gets not before from an empty ICT Request Token', () => {
  expect(() => new IctRequestToken().hasNotBefore()).not.toThrow();
  expect(new IctRequestToken().hasNotBefore()).toBe(false);

  expect(() => new IctRequestToken().getNotBefore()).not.toThrow();
  expect(new IctRequestToken().getNotBefore()).toBeUndefined();

  expect(() => new IctRequestToken().getNotBeforeDate()).not.toThrow();
  expect(new IctRequestToken().getNotBeforeDate()).toBeUndefined();
});

test('sets not before to an empty ICT Request Token', () => {
  expect(() => new IctRequestToken().setNotBefore()).not.toThrow();
  expect(() => new IctRequestToken().setNotBefore(1679612400)).not.toThrow();
  expect(() => new IctRequestToken().setNotBefore(new Date('2023-03-24 00:00:00'))).not.toThrow();

  expect(() => new IctRequestToken().setIssuedAt(-1)).toThrow();
  expect(() => new IctRequestToken().setIssuedAt(Infinity)).toThrow();
  expect(() => new IctRequestToken().setIssuedAt(Number.NEGATIVE_INFINITY)).toThrow();
  expect(() => new IctRequestToken().setIssuedAt(Number.NaN)).toThrow();

  expect(new IctRequestToken().setNotBefore()).toBeInstanceOf(IctRequestToken);
  expect(new IctRequestToken().setNotBefore(1679612400)).toBeInstanceOf(IctRequestToken);
  expect(new IctRequestToken().setNotBefore(new Date('2023-03-24 00:00:00'))).toBeInstanceOf(IctRequestToken);

  expect(new IctRequestToken().setNotBefore().hasNotBefore()).toBe(true);
  expect(new IctRequestToken().setNotBefore(1679612400).hasNotBefore()).toBe(true);
  expect(new IctRequestToken().setNotBefore(new Date('2023-03-24 00:00:00')).hasNotBefore()).toBe(true);

  expect(new IctRequestToken().setNotBefore().getNotBefore()).toBeLessThanOrEqual(Math.ceil(Date.now() / 1000));
  expect(new IctRequestToken().setIssuedAt(1679612400).setNotBefore().getNotBefore()).toBe(1679612400);
  expect(new IctRequestToken().setNotBefore(1679612400).getNotBefore()).toBe(1679612400);
  expect(new IctRequestToken().setNotBefore(new Date('2023-03-24 00:00:00')).getNotBefore()).toBe(1679612400);

  expect(new IctRequestToken().setIssuedAt(1679612400).setNotBefore().getNotBeforeDate()).toEqual(new Date('2023-03-24 00:00:00'));
  expect(new IctRequestToken().setNotBefore(1679612400).getNotBeforeDate()).toEqual(new Date('2023-03-24 00:00:00'));
  expect(new IctRequestToken().setNotBefore(new Date('2023-03-24 00:00:00')).getNotBeforeDate()).toEqual(new Date('2023-03-24 00:00:00'));
});

test('gets issued at from an empty ICT Request Token', () => {
  expect(() => new IctRequestToken().hasExpirationTime()).not.toThrow();
  expect(new IctRequestToken().hasExpirationTime()).toBe(false);

  expect(() => new IctRequestToken().getExpirationTime()).not.toThrow();
  expect(new IctRequestToken().getExpirationTime()).toBeUndefined();

  expect(() => new IctRequestToken().getExpirationTimeDate()).not.toThrow();
  expect(new IctRequestToken().getExpirationTimeDate()).toBeUndefined();
});

test('sets issued at to an empty ICT Request Token', () => {
  expect(() => new IctRequestToken().setExpirationTime(1679612400)).not.toThrow();
  expect(() => new IctRequestToken().setExpirationTime(new Date('2023-03-24 00:00:00'))).not.toThrow();

  expect(() => new IctRequestToken().setExpirationTime(-1)).toThrow();
  expect(() => new IctRequestToken().setExpirationTime(Infinity)).toThrow();
  expect(() => new IctRequestToken().setExpirationTime(Number.NEGATIVE_INFINITY)).toThrow();
  expect(() => new IctRequestToken().setExpirationTime(Number.NaN)).toThrow();

  expect(new IctRequestToken().setExpirationTime(1679612400)).toBeInstanceOf(IctRequestToken);
  expect(new IctRequestToken().setExpirationTime(new Date('2023-03-24 00:00:00'))).toBeInstanceOf(IctRequestToken);

  expect(new IctRequestToken().setExpirationTime(1679612400).hasExpirationTime()).toBe(true);
  expect(new IctRequestToken().setExpirationTime(new Date('2023-03-24 00:00:00')).hasExpirationTime()).toBe(true);

  expect(new IctRequestToken().setExpirationTime(1679612400).getExpirationTime()).toBe(1679612400);
  expect(new IctRequestToken().setExpirationTime(new Date('2023-03-24 00:00:00')).getExpirationTime()).toBe(1679612400);

  expect(new IctRequestToken().setExpirationTime(1679612400).getExpirationTimeDate()).toEqual(new Date('2023-03-24 00:00:00'));
  expect(new IctRequestToken().setExpirationTime(new Date('2023-03-24 00:00:00')).getExpirationTimeDate()).toEqual(new Date('2023-03-24 00:00:00'));
});

test('gets token claims from an empty ICT Request Token', () => {
  expect(() => new IctRequestToken().hasTokenClaims()).not.toThrow();
  expect(new IctRequestToken().hasTokenClaims()).toBe(false);

  expect(() => new IctRequestToken().getTokenClaims()).not.toThrow();
  expect(new IctRequestToken().getTokenClaims()).toBeUndefined();
});

test('sets token claims to an empty ICT Request Token', () => {
  expect(() => new IctRequestToken().setTokenClaims({})).not.toThrow();
  expect(() => new IctRequestToken().setTokenClaims({
    'sub': null, 
  })).not.toThrow();
  expect(() => new IctRequestToken().setTokenClaims({
    'sub': {
      essential: true,
      value: 'test',
    },
  })).not.toThrow();
  expect(() => new IctRequestToken().setTokenClaims({
    'sub': {
      essential: false,
      values: [ 'test1', 'test2' ],
    },
  })).not.toThrow();
  expect(() => new IctRequestToken().setTokenClaims({
    'sub': {
      values: [ 'test', 'test' ],
    },
  })).not.toThrow();
  expect(() => new IctRequestToken().setTokenClaims({
    'sub': {
      value: 'test',
      values: [ 'test1', 'test2' ],
    },
  })).toThrow();

  expect(new IctRequestToken().setTokenClaims({})).toBeInstanceOf(IctRequestToken);
  expect(new IctRequestToken().setTokenClaims({
    'sub': null, 
  })).toBeInstanceOf(IctRequestToken);
  expect(new IctRequestToken().setTokenClaims({
    'sub': {
      essential: true,
      value: 'test',
    },
  })).toBeInstanceOf(IctRequestToken);
  expect(new IctRequestToken().setTokenClaims({
    'sub': {
      essential: false,
      values: [ 'test1', 'test2' ],
    },
  })).toBeInstanceOf(IctRequestToken);
  expect(new IctRequestToken().setTokenClaims({
    'sub': {
      values: [ 'test', 'test' ],
    },
  })).toBeInstanceOf(IctRequestToken);

  expect(new IctRequestToken().setTokenClaims({}).hasTokenClaims()).toBe(false);
  expect(new IctRequestToken().setTokenClaims({
    'sub': null, 
  }).hasTokenClaims()).toBe(true);
  expect(new IctRequestToken().setTokenClaims({
    'sub': {
      essential: true,
      value: 'test',
    },
  }).hasTokenClaims()).toBe(true);
  expect(new IctRequestToken().setTokenClaims({
    'sub': {
      essential: false,
      values: [ 'test1', 'test2' ],
    },
  }).hasTokenClaims()).toBe(true);
  expect(new IctRequestToken().setTokenClaims({
    'sub': {
      values: [ 'test', 'test' ],
    },
  }).hasTokenClaims()).toBe(true);

  expect(new IctRequestToken().setTokenClaims({}).getTokenClaims()).toBeUndefined();
  expect(new IctRequestToken().setTokenClaims({
    'sub': null, 
  }).getTokenClaims()?.sub).toBeNull();
  expect(new IctRequestToken().setTokenClaims({
    'sub': {
      essential: true,
      value: 'test',
    },
  }).getTokenClaims()?.sub).toMatchObject({
    essential: true,
    value: 'test',
  });
  expect(new IctRequestToken().setTokenClaims({
    'sub': {
      essential: false,
      values: [ 'test1', 'test2' ],
    },
  }).getTokenClaims()?.sub).toMatchObject({
    essential: false,
    values: [ 'test1', 'test2' ],
  });
  expect(new IctRequestToken().setTokenClaims({
    'sub': {
      values: [ 'test', 'test' ],
    },
  }).getTokenClaims()?.sub).toMatchObject({
    essential: false,
    value: 'test',
  });
});

test('generates IRT header object', async () => {
  const publicKeyJwk = {
    kty: 'EC',
    crv: 'P-384',
    x: '5nWEPU3raA30tgZG5Vtzp28xbkqR7YdxQSiRnqdtdi3GO_-nOHPmVR3gm7SWWDJT',
    y: '7Y2iMcV5ogaY0Gqp6QL5h7GYgl0IoipwmQT7URym-6DIWhJZNk7RnoPbPddJslIW',
  };
  const publicKey = await crypto.webcrypto.subtle.importKey('jwk', publicKeyJwk,
    {
      name: 'ECDSA',
      namedCurve: 'P-384',
    }, true, ['verify']
  );

  await expect(new IctRequestToken().getHeaderObject()).rejects.toThrow();
  await expect(new IctRequestToken().setPublicKey(publicKey).getHeaderObject()).resolves.not.toThrow();

  async () => expect(new IctRequestToken().setPublicKey(publicKey).getHeaderObject()).resolves.toMatchObject({
    typ: 'JWT+IRT',
    alg: 'ES384',
    jwk: publicKeyJwk,
  });
});

test('generates IRT header string', async () => {
  const publicKeyJwk = {
    kty: 'EC',
    crv: 'P-384',
    x: '5nWEPU3raA30tgZG5Vtzp28xbkqR7YdxQSiRnqdtdi3GO_-nOHPmVR3gm7SWWDJT',
    y: '7Y2iMcV5ogaY0Gqp6QL5h7GYgl0IoipwmQT7URym-6DIWhJZNk7RnoPbPddJslIW',
  };
  const publicKey = await crypto.webcrypto.subtle.importKey('jwk', publicKeyJwk,
    {
      name: 'ECDSA',
      namedCurve: 'P-384',
    }, true, ['verify']
  );
  const headerBase64url = 'eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCtJUlQiLCJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTM4NCIsIngiOiI1bldFUFUzcmFBMzB0Z1pHNVZ0enAyOHhia3FSN1lkeFFTaVJucWR0ZGkzR09fLW5PSFBtVlIzZ203U1dXREpUIiwieSI6IjdZMmlNY1Y1b2dhWTBHcXA2UUw1aDdHWWdsMElvaXB3bVFUN1VSeW0tNkRJV2hKWk5rN1Jub1BiUGRkSnNsSVcifX0';

  async () => expect(new IctRequestToken().getHeaderString()).rejects.toThrow();
  expect(() => new IctRequestToken().setPublicKey(publicKey).getHeaderString()).not.toThrow();

  async () => expect(new IctRequestToken().setPublicKey(publicKey).getHeaderString()).toBe(headerBase64url);
});

test('generates IRT payload object', () => {
  const iss = 'https://issuer.example.org';
  const sub = 'subject';
  const aud = 'audience';
  const iat = 1679612400;
  const nbf = 1679612400;
  const exp = 1679616000;
  const jti = 'jti';
  const nonce = 'nonce';
  const token_claims: IrtClaimsSpecification = {
    nonce: {
      essential: true,
      value: 'random_nonce',
    },
  };

  expect(() => new IctRequestToken().getPayloadObject()).toThrow();
  expect(() => new IctRequestToken().setIssuer(iss).getPayloadObject()).toThrow();
  expect(() => new IctRequestToken().setIssuer(iss).setSubject(sub).getPayloadObject()).toThrow();
  expect(() => new IctRequestToken().setIssuer(iss).setSubject(sub).setAudience(aud).getPayloadObject()).toThrow();
  expect(() => new IctRequestToken().setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).getPayloadObject()).toThrow();
  expect(() => new IctRequestToken().setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).getPayloadObject()).not.toThrow();

  expect(new IctRequestToken()
    .setIssuer(iss)
    .setSubject(sub)
    .setAudience(aud)
    .setIssuedAt(iat)
    .setExpirationTime(exp)
    .getPayloadObject()
  ).toMatchObject({
    iss,
    sub,
    aud,
    iat,
    exp,
  });
  expect(new IctRequestToken()
    .setIssuer(iss)
    .setSubject(sub)
    .setAudience(aud)
    .setIssuedAt(iat)
    .setExpirationTime(exp)
    .setJti(jti)
    .setNonce(nonce)
    .setNotBefore(nbf)
    .setTokenClaims(token_claims)
    .getPayloadObject()
  ).toMatchObject({
    iss,
    sub,
    aud,
    iat,
    exp,
    jti,
    nonce,
    token_claims,
  });
});

test('generates IRT payload string', () => {
  const iss = 'https://issuer.example.org';
  const sub = 'subject';
  const aud = 'audience';
  const iat = 1679612400;
  const nbf = 1679612400;
  const exp = 1679616000;
  const jti = 'jti';
  const nonce = 'nonce';
  const token_claims = {
    nonce: {
      essential: true,
      value: 'random_nonce',
    },
  };
  const minPayloadBase64url = 'eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLm9yZyIsInN1YiI6InN1YmplY3QiLCJhdWQiOiJhdWRpZW5jZSIsImlhdCI6MTY3OTYxMjQwMCwiZXhwIjoxNjc5NjE2MDAwfQ';
  const maxPayloadBase64url = 'eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLm9yZyIsInN1YiI6InN1YmplY3QiLCJhdWQiOiJhdWRpZW5jZSIsImlhdCI6MTY3OTYxMjQwMCwibmJmIjoxNjc5NjEyNDAwLCJleHAiOjE2Nzk2MTYwMDAsImp0aSI6Imp0aSIsIm5vbmNlIjoibm9uY2UiLCJ0b2tlbl9jbGFpbXMiOnsibm9uY2UiOnsiZXNzZW50aWFsIjp0cnVlLCJ2YWx1ZSI6InJhbmRvbV9ub25jZSJ9fX0';

  expect(() => new IctRequestToken().getPayloadString()).toThrow();
  expect(() => new IctRequestToken().setIssuer(iss).getPayloadString()).toThrow();
  expect(() => new IctRequestToken().setIssuer(iss).setSubject(sub).getPayloadString()).toThrow();
  expect(() => new IctRequestToken().setIssuer(iss).setSubject(sub).setAudience(aud).getPayloadString()).toThrow();
  expect(() => new IctRequestToken().setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).getPayloadString()).toThrow();
  expect(() => new IctRequestToken().setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).getPayloadString()).not.toThrow();

  expect(new IctRequestToken()
    .setIssuer(iss)
    .setSubject(sub)
    .setAudience(aud)
    .setIssuedAt(iat)
    .setExpirationTime(exp)
    .getPayloadString()
  ).toEqual(minPayloadBase64url);
  expect(new IctRequestToken()
    .setIssuer(iss)
    .setSubject(sub)
    .setAudience(aud)
    .setIssuedAt(iat)
    .setExpirationTime(exp)
    .setJti(jti)
    .setNonce(nonce)
    .setNotBefore(nbf)
    .setTokenClaims(token_claims)
    .getPayloadString()
  ).toEqual(maxPayloadBase64url);
});

test('generates IRT header and payload string', async () => {
  const publicKeyJwk = {
    kty: 'EC',
    crv: 'P-384',
    x: '5nWEPU3raA30tgZG5Vtzp28xbkqR7YdxQSiRnqdtdi3GO_-nOHPmVR3gm7SWWDJT',
    y: '7Y2iMcV5ogaY0Gqp6QL5h7GYgl0IoipwmQT7URym-6DIWhJZNk7RnoPbPddJslIW',
  };
  const publicKey = await crypto.webcrypto.subtle.importKey('jwk', publicKeyJwk,
    {
      name: 'ECDSA',
      namedCurve: 'P-384',
    }, true, ['verify']
  );
  const headerBase64url = 'eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCtJUlQiLCJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTM4NCIsIngiOiI1bldFUFUzcmFBMzB0Z1pHNVZ0enAyOHhia3FSN1lkeFFTaVJucWR0ZGkzR09fLW5PSFBtVlIzZ203U1dXREpUIiwieSI6IjdZMmlNY1Y1b2dhWTBHcXA2UUw1aDdHWWdsMElvaXB3bVFUN1VSeW0tNkRJV2hKWk5rN1Jub1BiUGRkSnNsSVcifX0';

  const iss = 'https://issuer.example.org';
  const sub = 'subject';
  const aud = 'audience';
  const iat = 1679612400;
  const nbf = 1679612400;
  const exp = 1679616000;
  const jti = 'jti';
  const nonce = 'nonce';
  const token_claims = {
    nonce: {
      essential: true,
      value: 'random_nonce',
    },
  };
  const minPayloadBase64url = 'eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLm9yZyIsInN1YiI6InN1YmplY3QiLCJhdWQiOiJhdWRpZW5jZSIsImlhdCI6MTY3OTYxMjQwMCwiZXhwIjoxNjc5NjE2MDAwfQ';
  const maxPayloadBase64url = 'eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLm9yZyIsInN1YiI6InN1YmplY3QiLCJhdWQiOiJhdWRpZW5jZSIsImlhdCI6MTY3OTYxMjQwMCwibmJmIjoxNjc5NjEyNDAwLCJleHAiOjE2Nzk2MTYwMDAsImp0aSI6Imp0aSIsIm5vbmNlIjoibm9uY2UiLCJ0b2tlbl9jbGFpbXMiOnsibm9uY2UiOnsiZXNzZW50aWFsIjp0cnVlLCJ2YWx1ZSI6InJhbmRvbV9ub25jZSJ9fX0';

  async () => expect(new IctRequestToken().getHeaderAndPayloadString()).rejects.toThrow();
  async () => expect(new IctRequestToken().getHeaderAndPayloadString()).rejects.toThrow();
  async () => expect(new IctRequestToken().setIssuer(iss).getHeaderAndPayloadString()).rejects.toThrow();
  async () => expect(new IctRequestToken().setIssuer(iss).setSubject(sub).getHeaderAndPayloadString()).rejects.toThrow();
  async () => expect(new IctRequestToken().setIssuer(iss).setSubject(sub).setAudience(aud).getHeaderAndPayloadString()).rejects.toThrow();
  async () => expect(new IctRequestToken().setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).getHeaderAndPayloadString()).rejects.toThrow();
  async () => expect(new IctRequestToken().setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).getHeaderAndPayloadString()).rejects.toThrow();
  async () => expect(new IctRequestToken().setPublicKey(publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).getHeaderAndPayloadString()).rejects.not.toThrow();

  async () => expect(new IctRequestToken()
    .setPublicKey(publicKey)
    .setIssuer(iss)
    .setSubject(sub)
    .setAudience(aud)
    .setIssuedAt(iat)
    .setExpirationTime(exp)
    .getHeaderAndPayloadString()
  ).resolves.toBe(`${headerBase64url}.${minPayloadBase64url}`);
  async () => expect(new IctRequestToken()
    .setPublicKey(publicKey)
    .setIssuer(iss)
    .setSubject(sub)
    .setAudience(aud)
    .setIssuedAt(iat)
    .setExpirationTime(exp)
    .setJti(jti)
    .setNonce(nonce)
    .setNotBefore(nbf)
    .setTokenClaims(token_claims)
    .getPayloadString()
  ).resolves.toBe(`${headerBase64url}.${maxPayloadBase64url}`);
});

test('signs the IRT', async () => {
  // Create keys.
  const [
    ec256KeyPair,
    ec384KeyPair,
    ec512KeyPair,
    rsaEncKeyPair,
    rs256KeyPair,
    rs384KeyPair,
    rs512KeyPair,
    hs512Key,
    ps256KeyPair,
    ps384KeyPair,
    ps512KeyPair,
  ] = await Promise.all([
    crypto.subtle.generateKey({
      name: 'ECDSA', namedCurve: 'P-256', 
    }, false, ['sign', 'verify']),
    crypto.subtle.generateKey({
      name: 'ECDSA', namedCurve: 'P-384', 
    }, false, ['sign', 'verify']),
    crypto.subtle.generateKey({
      name: 'ECDSA', namedCurve: 'P-521', 
    }, false, ['sign', 'verify']),
    crypto.subtle.generateKey({
      name: 'RSA-OAEP', modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256',
    }, false, ['encrypt', 'decrypt']),
    crypto.subtle.generateKey({
      name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256',
    }, false, ['sign', 'verify']),
    crypto.subtle.generateKey({
      name: 'RSASSA-PKCS1-v1_5', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-384',
    }, false, ['sign', 'verify']),
    crypto.subtle.generateKey({
      name: 'RSASSA-PKCS1-v1_5', modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-512',
    }, false, ['sign', 'verify']),
    crypto.subtle.generateKey({
      name: 'HMAC', hash: {
        name: 'SHA-512', 
      },
    }, false, ['sign', 'verify']),
    crypto.subtle.generateKey({
      name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256',
    }, false, ['sign', 'verify']),
    crypto.subtle.generateKey({
      name: 'RSA-PSS', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-384',
    }, false, ['sign', 'verify']),
    crypto.subtle.generateKey({
      name: 'RSA-PSS', modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-512',
    }, false, ['sign', 'verify']),
  ]);

  const iss = 'https://issuer.example.org';
  const sub = 'subject';
  const aud = 'audience';
  const iat = 1679612400;
  const exp = 1679616000;

  // Test to throw if claims are missing.
  await expect(new IctRequestToken().sign(ec256KeyPair.privateKey)).rejects.toThrow();
  await expect(new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).sign(ec256KeyPair.privateKey)).rejects.toThrow();
  await expect(new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).setIssuer(iss).sign(ec256KeyPair.privateKey)).rejects.toThrow();
  await expect(new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).setIssuer(iss).setSubject(sub).sign(ec256KeyPair.privateKey)).rejects.toThrow();
  await expect(new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).sign(ec256KeyPair.privateKey)).rejects.toThrow();
  await expect(new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).sign(ec256KeyPair.privateKey)).rejects.toThrow();

  // Test to throw if wrong signing key is provided.
  await expect(new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ec256KeyPair.publicKey)).rejects.toThrow();
  await expect(new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(rsaEncKeyPair.publicKey)).rejects.toThrow();
  await expect(new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(hs512Key)).rejects.toThrow();

  await expect(new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ec256KeyPair.privateKey)).rejects.not.toThrow();
  await expect(new IctRequestToken().setPublicKey(ec384KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ec384KeyPair.privateKey)).rejects.not.toThrow();
  await expect(new IctRequestToken().setPublicKey(ec512KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ec512KeyPair.privateKey)).rejects.not.toThrow();
  await expect(new IctRequestToken().setPublicKey(rs256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(rs256KeyPair.privateKey)).rejects.not.toThrow();
  await expect(new IctRequestToken().setPublicKey(rs384KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(rs384KeyPair.privateKey)).rejects.not.toThrow();
  await expect(new IctRequestToken().setPublicKey(rs512KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(rs512KeyPair.privateKey)).rejects.not.toThrow();
  await expect(new IctRequestToken().setPublicKey(ps256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ps256KeyPair.privateKey)).rejects.not.toThrow();
  await expect(new IctRequestToken().setPublicKey(ps384KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ps384KeyPair.privateKey)).rejects.not.toThrow();
  await expect(new IctRequestToken().setPublicKey(ps512KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ps512KeyPair.privateKey)).rejects.not.toThrow();

  
});
