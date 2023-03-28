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
    rs256PublicKeyNoExt,
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
    crypto.subtle.generateKey({
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: {
        name: 'SHA-256',
      },
    }, true, ['sign', 'verify']).then(async keyPair => {
      return await crypto.subtle.importKey('jwk',
        await crypto.subtle.exportKey('jwk', keyPair.publicKey), {
          name: 'RSASSA-PKCS1-v1_5', hash: {
            name: 'SHA-256',
          },
        }, false, ['verify']
      );
    }),
  ]);

  // Verify that setting a public key of a non-extractable key pair does not throw.
  expect(() => new IctRequestToken().setPublicKey(rs256KeyPairNoExt.publicKey)).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(rs384KeyPairNoExt.publicKey)).not.toThrow();
  expect(() => new IctRequestToken().setPublicKey(rs512KeyPairNoExt.publicKey)).not.toThrow();

  // Verify that setting a private key does throw an error.
  expect(() => new IctRequestToken().setPublicKey(rs256KeyPair.privateKey)).toThrow();
  expect(() => new IctRequestToken().setPublicKey(rs384KeyPair.privateKey)).toThrow();
  expect(() => new IctRequestToken().setPublicKey(rs512KeyPair.privateKey)).toThrow();

  // Verify that setting a not-extractable public key throws an error.
  expect(() => new IctRequestToken().setPublicKey(rs256PublicKeyNoExt)).toThrow();

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

  expect(() => new IctRequestToken().setNotBefore(-1)).toThrow();
  expect(() => new IctRequestToken().setNotBefore(Infinity)).toThrow();
  expect(() => new IctRequestToken().setNotBefore(Number.NEGATIVE_INFINITY)).toThrow();
  expect(() => new IctRequestToken().setNotBefore(-1)).toThrow();
  expect(() => new IctRequestToken().setNotBefore(Number.NaN)).toThrow();

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
  await expect(new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(rsaEncKeyPair.privateKey)).rejects.toThrow();
  await expect(new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(hs512Key)).rejects.toThrow();
  await expect(new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ec384KeyPair.privateKey)).rejects.toThrow();
  await expect(new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(rs256KeyPair.privateKey)).rejects.toThrow();
  await expect(new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ps256KeyPair.privateKey)).rejects.toThrow();
  await expect(new IctRequestToken().setPublicKey(ps256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ps384KeyPair.privateKey)).rejects.toThrow();
  await expect(new IctRequestToken().setPublicKey(ps256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(rs256KeyPair.privateKey)).rejects.toThrow();
  await expect(new IctRequestToken().setPublicKey(ps256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ec256KeyPair.privateKey)).rejects.toThrow();
  await expect(new IctRequestToken().setPublicKey(rs256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(rs384KeyPair.privateKey)).rejects.toThrow();
  await expect(new IctRequestToken().setPublicKey(rs256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ec256KeyPair.privateKey)).rejects.toThrow();
  await expect(new IctRequestToken().setPublicKey(rs256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ps256KeyPair.privateKey)).rejects.toThrow();

  // Test to not throw if correct signing key is provided.
  await expect(new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ec256KeyPair.privateKey)).resolves.not.toThrow();
  await expect(new IctRequestToken().setPublicKey(ec384KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ec384KeyPair.privateKey)).resolves.not.toThrow();
  await expect(new IctRequestToken().setPublicKey(ec512KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ec512KeyPair.privateKey)).resolves.not.toThrow();
  await expect(new IctRequestToken().setPublicKey(rs256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(rs256KeyPair.privateKey)).resolves.not.toThrow();
  await expect(new IctRequestToken().setPublicKey(rs384KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(rs384KeyPair.privateKey)).resolves.not.toThrow();
  await expect(new IctRequestToken().setPublicKey(rs512KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(rs512KeyPair.privateKey)).resolves.not.toThrow();
  await expect(new IctRequestToken().setPublicKey(ps256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ps256KeyPair.privateKey)).resolves.not.toThrow();
  await expect(new IctRequestToken().setPublicKey(ps384KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ps384KeyPair.privateKey)).resolves.not.toThrow();
  await expect(new IctRequestToken().setPublicKey(ps512KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ps512KeyPair.privateKey)).resolves.not.toThrow();

  // Test if hasSignature() works correctly.
  await expect(new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ec256KeyPair.privateKey)).resolves.toBeInstanceOf(IctRequestToken);
  await expect((async () => {
    const token = await new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ec256KeyPair.privateKey);
    return token.hasSignature();
  })()).resolves.toBe(true);
  await expect((async () => {
    const token = await new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ec256KeyPair.privateKey);
    return token.setAudience('aud').hasSignature();
  })()).resolves.toBe(false);
  await expect((async () => {
    const token = await new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ec256KeyPair.privateKey);
    return token.setExpirationTime(Date.now() / 1000).hasSignature();
  })()).resolves.toBe(false);
  await expect((async () => {
    const token = await new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ec256KeyPair.privateKey);
    return token.setIssuedAt().hasSignature();
  })()).resolves.toBe(false);
  await expect((async () => {
    const token = await new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ec256KeyPair.privateKey);
    return token.setIssuer('iss').hasSignature();
  })()).resolves.toBe(false);
  await expect((async () => {
    const token = await new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ec256KeyPair.privateKey);
    return token.setJti('jti').hasSignature();
  })()).resolves.toBe(false);
  await expect((async () => {
    const token = await new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ec256KeyPair.privateKey);
    return token.setNonce('nonce').hasSignature();
  })()).resolves.toBe(false);
  await expect((async () => {
    const token = await new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ec256KeyPair.privateKey);
    return token.setNotBefore(Date.now()).hasSignature();
  })()).resolves.toBe(false);
  await expect((async () => {
    const token = await new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ec256KeyPair.privateKey);
    return token.setPublicKey(ec256KeyPair.publicKey).hasSignature();
  })()).resolves.toBe(false);
  await expect((async () => {
    const token = await new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ec256KeyPair.privateKey);
    return token.setSubject('sub').hasSignature();
  })()).resolves.toBe(false);
  await expect((async () => {
    const token = await new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ec256KeyPair.privateKey);
    return token.setTokenClaims({
      nonce: {
        value: 'nonce',
      },
    }).hasSignature();
  })()).resolves.toBe(false);
});

test('get IRT signature', async () => {
  // Create keys.
  const ec256KeyPair = await crypto.subtle.generateKey({
    name: 'ECDSA', namedCurve: 'P-256', 
  }, false, ['sign', 'verify']);

  const iss = 'https://issuer.example.org';
  const sub = 'subject';
  const aud = 'audience';
  const iat = 1679612400;
  const exp = 1679616000;

  // Test to throw if not signed.
  expect(() => new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).getSignatureString()).toThrow();
  expect(() => new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).getSignatureBytes()).toThrow();
  // Test to not throw if signed.
  await expect((async () => {
    const token = await new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ec256KeyPair.privateKey);
    return token.getSignatureString();
  })()).resolves.not.toThrow();
  await expect((async () => {
    const token = await new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ec256KeyPair.privateKey);
    return token.getSignatureBytes();
  })()).resolves.not.toThrow();

  // Test correct result.
  const publicKeyJson = {
    kty: 'RSA',
    e: 'AQAB',
    n: 'q8miK3ROI7yKEjkBot6q3MNsvpVhlaUzSs-37nWPlQ6t6C5s-2z-KZayU8_FMlmFSkuKpJ77v2zl-pJh3yDYbzxIS15SqsUrU4nF9gsozGAAHtaheXbQIqx9fZ-apNlv2ZmMGUWhKXvHsCHqopCaECkWBRMYrq3Lv1Qx-2CKc2Gqo6KxhtNaQ50sNOzUR9BbKO2BwS8iWo0Wj7HCLiN747VrSmiqRTJuQHD6SenNGsWzlqrOZk4HppN_k3h9llMPC0DeEdV0UsHoS_XgE4nam2lmtLZWyH4XW65VeexzyLCvMBh3rmS_XwOp3sHqJrlkRmx4Ht-U9pUpT_NFh-PKUQ',
  };
  const privateKeyJson = {
    kty: 'RSA',
    e: 'AQAB',
    n: 'q8miK3ROI7yKEjkBot6q3MNsvpVhlaUzSs-37nWPlQ6t6C5s-2z-KZayU8_FMlmFSkuKpJ77v2zl-pJh3yDYbzxIS15SqsUrU4nF9gsozGAAHtaheXbQIqx9fZ-apNlv2ZmMGUWhKXvHsCHqopCaECkWBRMYrq3Lv1Qx-2CKc2Gqo6KxhtNaQ50sNOzUR9BbKO2BwS8iWo0Wj7HCLiN747VrSmiqRTJuQHD6SenNGsWzlqrOZk4HppN_k3h9llMPC0DeEdV0UsHoS_XgE4nam2lmtLZWyH4XW65VeexzyLCvMBh3rmS_XwOp3sHqJrlkRmx4Ht-U9pUpT_NFh-PKUQ',
    d: 'FHZEuwzUNuUBBDkmlP4VV4zukcfs0vyVvro9xClcJCrWs6J-CDe8EXuZ-6oyqLPpkMctOT0Xqv4_aYiQoFmC9kL1sIaIbb9lEQMG4a8EGc3wjbvOiY-JrKujmfhOHQcqT76-pY756p1MFJKBpoH3W-fs78dNyBa6_2v5tSHTc_kytSqyrSTBuR5VsW9eIneb55DpbXzuD8ydsU_IfUsGRl7w2BNAGnZHtbA8Wp7jwnWjRAiliPj-Q96EzxpJXdKpwDV1HdQl5e3sxBWLHAUoX48TK1ADiIdJr9Odtgebw7w6VomLQNdbTwQr97wI7_uTNTuk0ngZJjH5ZQ8oDd6FHQ',
    dp: 'V06nkmniGU5xcW2GE2SpIk4Z7hrH_jNYl0yEW1ZeCZUtsYnCIgASzLGrwQ2ue0donX8tWG8GCsuFSXSRhZblNuSEIw1sdpZkyQslAoZ0Aix3_mi4zjOniDFkdNAN7lDcx3qTLWEU40sYThRfFRDv0XzcT-tfho8rCovMn-mUCqk',
    dq: 'SVcEfUq4kwubWbKiEKoi5V_wUpenF-5u-h9kq3UYN9zzFkdq6ASHGeipzXUIeDNfaDoifqT7UpWrHx9f2yzQKlgfBFTW6Nr6R9ljPLdUoAFhfhPKwrfHa9SsJ3TJyTuSYuAEibfRIiTEu6qF0_xu8bNqSXQerDL8mtmbR4DbzLE',
    p: '6M3ODo4-ZzSg5vhu1Xgu5u57qKO3hCDRbVtX2HLBRoHGCHOyC6WkA_aBZJG7uVEuBsn4tHKO4d92Os5jo62z27AJvqWF7T1Xt1apAO6MdBQwBqxvpXhyHTcwlN5Cr5kfuupiMypKf3Kh38J5tqGUU2ASzFrnSwBJmF8RJDUexVU',
    q: 'vOd4A7HSgBo5SDhM-2oAZcS8X4q-CKsIA6-oiRfSaWn-0zt0Q0jLdteCqEs83PwsObopYUR6GYaES0ih5Fu2V7zN2-YIwBG9TUR8-48BPa0HhTmE1aW2EMiAbIK6ozVH5xJ3dyEmiNAOfh8A_bqQ8dEx1RUhSTkJHSjpHJNUsQ0',
    qi: 'aNHUZb8O8ryLdY9GoE1br5z7q6ycF_t8e71vLkKuXwo75HROIIRFnRoTtvnH0klbgv72YG1C7MZTjEXNi6w9gexwxmtvvuswjQx1Mrzy_5-fD386TTNprZt-D_lPrKHGqdCTKSwuOfpee9sjZuyaQjwmjZvZz2YwCdzbTcjIdgM',
  };
  const publicKey = await crypto.webcrypto.subtle.importKey('jwk', publicKeyJson, {
    name: 'RSASSA-PKCS1-v1_5', hash: {
      name: 'SHA-256', 
    }, 
  }, true, ['verify']);
  const privateKey = await crypto.webcrypto.subtle.importKey('jwk', privateKeyJson, {
    name: 'RSASSA-PKCS1-v1_5', hash: {
      name: 'SHA-256', 
    }, 
  }, false, ['sign']);

  const token = await new IctRequestToken().setPublicKey(publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(privateKey);
  expect(token.getSignatureString()).toBe('HKzMC_giMs2Jo5MQ8mwoAr2INix3hLM_SwGQxClYwbLSrswTpl1xdtEzBKF2YwBerhAE04-lpha9w-7BepMAuD4KEAMaAd8ZsDCQW2pPz7dC5r2kusQHlkv_-bt_qVPjUbbV6jVp_S2ixSaM5Wyq0FgmFZ8uOFw1epRoxM8ViLyucSzlq2DcmjcH_v4WZ6E2s12Te_sYxJ-lV70vkUAD971oLNzBnxdiz-vYjAzMibyx4R9TIqYagak_KDVXfy-uKzRnh_nNHMOdwm-eGnqIhxHVjuWHy4-yxhxiUHypRGLvIxm0qeXsRc1ThG4Mc3xf_FTcS9nUGw9p1Tf2ouQazA');
});

test('get IRT token string', async () => {
  // Create keys.
  const ec256KeyPair = await crypto.subtle.generateKey({
    name: 'ECDSA', namedCurve: 'P-256', 
  }, false, ['sign', 'verify']);

  const iss = 'https://issuer.example.org';
  const sub = 'subject';
  const aud = 'audience';
  const iat = 1679612400;
  const exp = 1679616000;

  // Test to throw if not signed.
  await expect(() => new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).getTokenString()).rejects.toThrow();
  // Test to not throw if signed.
  await expect((async () => {
    const token = await new IctRequestToken().setPublicKey(ec256KeyPair.publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(ec256KeyPair.privateKey);
    return token.getTokenString();
  })()).resolves.not.toThrow();

  // Test correct result.
  const publicKeyJson = {
    kty: 'RSA',
    e: 'AQAB',
    n: 'q8miK3ROI7yKEjkBot6q3MNsvpVhlaUzSs-37nWPlQ6t6C5s-2z-KZayU8_FMlmFSkuKpJ77v2zl-pJh3yDYbzxIS15SqsUrU4nF9gsozGAAHtaheXbQIqx9fZ-apNlv2ZmMGUWhKXvHsCHqopCaECkWBRMYrq3Lv1Qx-2CKc2Gqo6KxhtNaQ50sNOzUR9BbKO2BwS8iWo0Wj7HCLiN747VrSmiqRTJuQHD6SenNGsWzlqrOZk4HppN_k3h9llMPC0DeEdV0UsHoS_XgE4nam2lmtLZWyH4XW65VeexzyLCvMBh3rmS_XwOp3sHqJrlkRmx4Ht-U9pUpT_NFh-PKUQ',
  };
  const privateKeyJson = {
    kty: 'RSA',
    e: 'AQAB',
    n: 'q8miK3ROI7yKEjkBot6q3MNsvpVhlaUzSs-37nWPlQ6t6C5s-2z-KZayU8_FMlmFSkuKpJ77v2zl-pJh3yDYbzxIS15SqsUrU4nF9gsozGAAHtaheXbQIqx9fZ-apNlv2ZmMGUWhKXvHsCHqopCaECkWBRMYrq3Lv1Qx-2CKc2Gqo6KxhtNaQ50sNOzUR9BbKO2BwS8iWo0Wj7HCLiN747VrSmiqRTJuQHD6SenNGsWzlqrOZk4HppN_k3h9llMPC0DeEdV0UsHoS_XgE4nam2lmtLZWyH4XW65VeexzyLCvMBh3rmS_XwOp3sHqJrlkRmx4Ht-U9pUpT_NFh-PKUQ',
    d: 'FHZEuwzUNuUBBDkmlP4VV4zukcfs0vyVvro9xClcJCrWs6J-CDe8EXuZ-6oyqLPpkMctOT0Xqv4_aYiQoFmC9kL1sIaIbb9lEQMG4a8EGc3wjbvOiY-JrKujmfhOHQcqT76-pY756p1MFJKBpoH3W-fs78dNyBa6_2v5tSHTc_kytSqyrSTBuR5VsW9eIneb55DpbXzuD8ydsU_IfUsGRl7w2BNAGnZHtbA8Wp7jwnWjRAiliPj-Q96EzxpJXdKpwDV1HdQl5e3sxBWLHAUoX48TK1ADiIdJr9Odtgebw7w6VomLQNdbTwQr97wI7_uTNTuk0ngZJjH5ZQ8oDd6FHQ',
    dp: 'V06nkmniGU5xcW2GE2SpIk4Z7hrH_jNYl0yEW1ZeCZUtsYnCIgASzLGrwQ2ue0donX8tWG8GCsuFSXSRhZblNuSEIw1sdpZkyQslAoZ0Aix3_mi4zjOniDFkdNAN7lDcx3qTLWEU40sYThRfFRDv0XzcT-tfho8rCovMn-mUCqk',
    dq: 'SVcEfUq4kwubWbKiEKoi5V_wUpenF-5u-h9kq3UYN9zzFkdq6ASHGeipzXUIeDNfaDoifqT7UpWrHx9f2yzQKlgfBFTW6Nr6R9ljPLdUoAFhfhPKwrfHa9SsJ3TJyTuSYuAEibfRIiTEu6qF0_xu8bNqSXQerDL8mtmbR4DbzLE',
    p: '6M3ODo4-ZzSg5vhu1Xgu5u57qKO3hCDRbVtX2HLBRoHGCHOyC6WkA_aBZJG7uVEuBsn4tHKO4d92Os5jo62z27AJvqWF7T1Xt1apAO6MdBQwBqxvpXhyHTcwlN5Cr5kfuupiMypKf3Kh38J5tqGUU2ASzFrnSwBJmF8RJDUexVU',
    q: 'vOd4A7HSgBo5SDhM-2oAZcS8X4q-CKsIA6-oiRfSaWn-0zt0Q0jLdteCqEs83PwsObopYUR6GYaES0ih5Fu2V7zN2-YIwBG9TUR8-48BPa0HhTmE1aW2EMiAbIK6ozVH5xJ3dyEmiNAOfh8A_bqQ8dEx1RUhSTkJHSjpHJNUsQ0',
    qi: 'aNHUZb8O8ryLdY9GoE1br5z7q6ycF_t8e71vLkKuXwo75HROIIRFnRoTtvnH0klbgv72YG1C7MZTjEXNi6w9gexwxmtvvuswjQx1Mrzy_5-fD386TTNprZt-D_lPrKHGqdCTKSwuOfpee9sjZuyaQjwmjZvZz2YwCdzbTcjIdgM',
  };
  const publicKey = await crypto.webcrypto.subtle.importKey('jwk', publicKeyJson, {
    name: 'RSASSA-PKCS1-v1_5', hash: {
      name: 'SHA-256', 
    }, 
  }, true, ['verify']);
  const privateKey = await crypto.webcrypto.subtle.importKey('jwk', privateKeyJson, {
    name: 'RSASSA-PKCS1-v1_5', hash: {
      name: 'SHA-256', 
    }, 
  }, false, ['sign']);

  const token = await new IctRequestToken().setPublicKey(publicKey).setIssuer(iss).setSubject(sub).setAudience(aud).setIssuedAt(iat).setExpirationTime(exp).sign(privateKey);
  await expect(token.getTokenString()).resolves.toBe('eyJ0eXAiOiJKV1QrSVJUIiwiYWxnIjoiUlMyNTYiLCJqd2siOnsia3R5IjoiUlNBIiwibiI6InE4bWlLM1JPSTd5S0Vqa0JvdDZxM01Oc3ZwVmhsYVV6U3MtMzduV1BsUTZ0NkM1cy0yei1LWmF5VThfRk1sbUZTa3VLcEo3N3YyemwtcEpoM3lEWWJ6eElTMTVTcXNVclU0bkY5Z3NvekdBQUh0YWhlWGJRSXF4OWZaLWFwTmx2MlptTUdVV2hLWHZIc0NIcW9wQ2FFQ2tXQlJNWXJxM0x2MVF4LTJDS2MyR3FvNkt4aHROYVE1MHNOT3pVUjlCYktPMkJ3UzhpV28wV2o3SENMaU43NDdWclNtaXFSVEp1UUhENlNlbk5Hc1d6bHFyT1prNEhwcE5fazNoOWxsTVBDMERlRWRWMFVzSG9TX1hnRTRuYW0ybG10TFpXeUg0WFc2NVZlZXh6eUxDdk1CaDNybVNfWHdPcDNzSHFKcmxrUm14NEh0LVU5cFVwVF9ORmgtUEtVUSIsImUiOiJBUUFCIn19.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLm9yZyIsInN1YiI6InN1YmplY3QiLCJhdWQiOiJhdWRpZW5jZSIsImlhdCI6MTY3OTYxMjQwMCwiZXhwIjoxNjc5NjE2MDAwfQ.HKzMC_giMs2Jo5MQ8mwoAr2INix3hLM_SwGQxClYwbLSrswTpl1xdtEzBKF2YwBerhAE04-lpha9w-7BepMAuD4KEAMaAd8ZsDCQW2pPz7dC5r2kusQHlkv_-bt_qVPjUbbV6jVp_S2ixSaM5Wyq0FgmFZ8uOFw1epRoxM8ViLyucSzlq2DcmjcH_v4WZ6E2s12Te_sYxJ-lV70vkUAD971oLNzBnxdiz-vYjAzMibyx4R9TIqYagak_KDVXfy-uKzRnh_nNHMOdwm-eGnqIhxHVjuWHy4-yxhxiUHypRGLvIxm0qeXsRc1ThG4Mc3xf_FTcS9nUGw9p1Tf2ouQazA');
});
