# Key Pair Generation Examples

Use the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) to generate asymmetric key pairs.

It is highly recommended to generate non-extractable key pairs by setting the second parameter of the `generateKey` function to `false`!


## Elliptic Curve Key Pairs

```typescript
// ES256 Key Pair:
await crypto.subtle.generateKey(
  {
    name: 'ECDSA',
    namedCurve: 'P-256',
  },
  false,
  ['sign', 'verify'],
);

// ES384 Key Pair:
await crypto.subtle.generateKey(
  {
    name: 'ECDSA',
    namedCurve: 'P-384',
  },
  false,
  ['sign', 'verify'],
);

// ES512 Key Pair:
await crypto.subtle.generateKey(
  {
    name: 'ECDSA',
    namedCurve: 'P-521',
  },
  false,
  ['sign', 'verify'],
);
```


## RSA Key Pairs

```typescript
// RS256 Key Pair:
await crypto.subtle.generateKey(
  {
    name: 'RSASSA-PKCS1-v1_5',
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-256",
  },
  false,
  ['sign', 'verify'],
);

// RS384 Key Pair:
await crypto.subtle.generateKey(
  {
    name: 'RSASSA-PKCS1-v1_5',
    modulusLength: 3072,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-384",
  },
  false,
  ['sign', 'verify'],
);

// RS512 Key Pair:
await crypto.subtle.generateKey(
  {
    name: 'RSASSA-PKCS1-v1_5',
    modulusLength: 4096,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-512",
  },
  false,
  ['sign', 'verify'],
);
```


## RSA-PSS Key Pairs

```typescript
// PS256 Key Pair:
await crypto.subtle.generateKey(
  {
    name: 'RSA-PSS',
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-256",
  },
  false,
  ['sign', 'verify'],
);

// PS384 Key Pair:
await crypto.subtle.generateKey(
  {
    name: 'RSA-PSS',
    modulusLength: 3072,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-384",
  },
  false,
  ['sign', 'verify'],
);

// PS512 Key Pair:
await crypto.subtle.generateKey(
  {
    name: 'RSA-PSS',
    modulusLength: 4096,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-512",
  },
  false,
  ['sign', 'verify'],
);
```
