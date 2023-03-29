# OIDC-Squared

The OIDC² library for Browsers and Node.

## Install

```bash
npm install oidc-squared
```


## Documentation

### ICT Request Token

#### Supported Signing Algorithms

| Algorithm | Supported |
|-----------|-----------|
| ES256     | ✅         |
| ES384     | ✅         |
| ES512     | ✅         |
| RS256     | ✅         |
| RS384     | ✅         |
| RS512     | ✅         |
| PS256     | ✅         |
| PS384     | ✅         |
| PS512     | ✅         |
| EdDSA     | ❌         |

#### Generation Example

```typescript
import { IctRequestToken } from 'oidc-squared';

// Create a sufficient signing key pair. E.g., for ES384:
const keyPair = await crypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-384' },
  false,
  ['sign', 'verify']
);

const token = new IctRequestToken()             // Create new IRT.
  .setPublicKey(keyPair.publicKey)              // Set public key. (required)
  .setIssuer('my_client_id')                    // Set issuer identifier, e.g., your client ID. (required)
  .setSubject('my_user_id')                     // Set subject identifier, e.g., your user ID. (required)
  .setAudience('https://issuer.example.org')    // Set audience(s) identifier(s), e.g., your OpenID Provider's base URL. (required)
  .setIssuedAt()                                // Set issued at date to now (default) or provided timestamp. (required)
  .setNotBefore()                               // Set not before date to issued at (if already set) date, now (default), or provided timestamp. (optional)
  .setExpirationTime((Date.now() / 1000) + 60)  // Set the expiration date in 1 minute. (required)
  .setJti()                                     // Set a JWT ID to a random UUID (default) or provided string. (optional)
  .setNonce()                                   // Set a nonce to a random base64 string (default) or provided string. (optional)
  .setTokenClaims({                             // Set desired claims for ID Certification Token. (optional)
    nonce: {                                    // Request a nonce.
      essential: true,                          // Make it essential to get a nonce.
      value: 'my_random_nonce'                  // Set it to the value 'my_random_nonce'.
    }
  });
await token.sign(privateKey);                   // Sign the IRT. (required)
const irt = await token.getTokenString();       // Convert the token to JWT string.
```

#### Validation Example

```typescript
import { IctRequestToken } from 'oidc-squared';

const irt = 'eyJ0eX[...]19.eyJ[...]fQ.HKzM[...]azA';              // ID Certification Token (shortened).

const token = await IctRequestToken.fromTokenString(irt);         // Create new IRT and verify validity.
// or
const token = await IctRequestToken.fromTokenString(irt, false);  // Create new IRT and do not verify validity.
// or
const token = await IctRequestToken.fromTokenString(irt, {        // Create new IRT and verify only signature.
  verifySignature: true,                                          // Verify signature.
  verifyTime: false,                                              // Do not verify time.
  verificationTime: Date.now() / 1000,                            // Set timestamp (with millisecond precision) of verification time.
  verificationTimeDelta: 60,                                      // Optional time delta to avoid time shifting errors.
});        
```
