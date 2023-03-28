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

// Create a sufficient key pair. Here for ES384:
const keyPair = await crypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-384' },
  false,
  ['sign', 'verify']
);

const token = new IctRequestToken()             // Create new IRT.
  .setPublicKey(keyPair.publicKey)              // Set public key.
  .setIssuer('my_client_id')                    // Set issuer identifier. Typically your client ID.
  .setSubject('my_user_id')                     // Set subject identifier. Typically your user ID.
  .setAudience('https://issuer.example.org')    // Set audience(s) identifier(s). Typically your OpenID Provider's base URL.
  .setIssuedAt()                                // Set issued at date to now.
  .setExpirationTime((Date.now() / 1000) + 60); // Set the expiration date in 1 minute.
await token.sign(privateKey);                   // Sign the IRT.
const irt = await token.getTokenString();       // Convert the token to JWT string.
```
