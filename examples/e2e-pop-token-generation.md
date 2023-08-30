# End-to-End Proof-of-Possession Token Generation

```typescript
import * as jose from 'jose';
import { SignE2EPoPToken } from 'oidc-squared';

// Calculate the JWK Thumbprint from the Client's public key.
const jkt = await jose.calculateJwkThumbprint(
  await jose.exportJWK(clientKeyPair.publicKey),
  'sha256',
);

// Create new E2E PoP Token:
//   This automatically sets:
//     - a newly generated UUID as "jti" (JWT ID) Claim.
//     - the current unix timestamp as "iat" (Issued At) Claim.
//     - the current unix timestamp + 300 seconds (= 5 minutes) as "exp" (Expiration) Claim.
const e2ePoPToken = new SignE2EPoPToken();

// Sets all header parameters manually:
e2ePoPToken.setProtectedHeader({
  typ: 'jwt+e2epop',  // This MUST be set to "jwt+e2epop" to identify it as an E2E PoP Token.
  alg: 'ES384',       // Insert the Client's signing algorithm here.
  jkt: jkt,           // Insert the calculated JWK Thumbprint from the Client's public key here.
});
// You can also set the thumbprint:
e2ePoPToken.setThumbprint(
  'ES384',  // Insert the Client's signing algorithm here.
  jkt,      // Insert the calculated JWK Thumbprint from the Client's public key here.
);

// Set the Issuer (typically the Client's Client ID):
e2ePoPToken.setIssuer('myclient');

// Set the Subject (typically the End-User's subject identifier):
e2ePoPToken.setSubject(subject);

// Set the Audience (typically the Relying Party's Client ID, the Relying Party's End-User Subject Identifier, or a session id that the Relying Party uniquely identifies with):
e2ePoPToken.setAudience('sessionid');
// This can also be an array:
e2ePoPToken.setAudience(['sessionid', 'bob']);

// Get now as unix timestamp with seconds-precision.
const now = Math.floor(Date.now() / 1000);

// Set Issued At to timestamp specified in variable `now`.
e2ePoPToken.setIssuedAt(now);
// Set Issued At to now:
e2ePoPToken.setIssuedAt();
// In both cases: If Expiration Claim was not yet specified, it will be set to "iat" + 300 seconds.

// (Optional) Set Not Before to timestamp specified in variable `now`:
e2ePoPToken.setNotBefore(now);
// (Optional) Set Not Before to "iat", or now, if not provided:
e2ePoPToken.setNotBefore();

// Set Expiration to specified timestamp.
e2ePoPToken.setExpirationTime(now + 60);

// Set the JWT ID to a Universally Unique Identifier (UUID).
e2ePoPToken.setJti();
// You can also set the JWT ID to an explicit Universally Unique Identifier (UUID).
e2ePoPToken.setJti(NonceGenerators.uuid().generate());
// You can also set the JWT ID to a random n-bytes (here: 16 bytes) long Base64-encoded string.
e2ePoPToken.setJti(NonceGenerators.base64(16).generate());

// Signs the E2E PoP Token using the provided private key and returns its token string.
const token = await e2ePoPToken.sign(clientKeyPair.privateKey);
```
