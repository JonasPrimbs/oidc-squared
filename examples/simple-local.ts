import * as jose from 'jose';
import { NonceGenerators, SignE2EPoPToken, SignICT, SignPoPToken, e2ePoPTokenVerify, ictVerify, popTokenVerify } from '../src';

// Prepare client:
const opBaseUrl = 'https://op.example.com';
const subject = 'alice';
const clientId = 'myclient';
const now = Math.floor(Date.now() / 1000);
const context = 'example-app';

// Generate client's signing key pair:
const clientKeyPair = await crypto.subtle.generateKey(
  {
    name: 'ECDSA',
    namedCurve: 'P-384',
  },
  false,
  ['sign', 'verify'],
);

// Generate Proof-of-Possession Token:
const popToken = await new SignPoPToken()
  .setProtectedHeader({
    typ: 'jwt+pop',
    alg: 'ES384',
    jwk: await crypto.subtle.exportKey('jwk', clientKeyPair.publicKey),
  })
  .setIssuer(clientId)
  .setSubject(subject)
  .setAudience(opBaseUrl)
  .setIssuedAt(now)
  .setNotBefore(now) // optional
  .setExpirationTime(now + 60)
  .setJti(NonceGenerators.base64(16).generate())
  .sign(clientKeyPair.privateKey);

// Verify PoP Token:
const popTokenResult = await popTokenVerify(popToken, {
  issuer: clientId,
  subject: subject,
  audience: opBaseUrl,
  maxTokenAge: 300,
});//.catch(e => console.error('Failed to verify PoP Token!', e));

// Create OpenID Provider's Key Pair:
const opKeyPair = await crypto.subtle.generateKey(
  {
    name: 'RSASSA-PKCS1-v1_5',
    modulusLength: 3072,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-384',
  },
  false,
  [ 'sign', 'verify' ],
);
const opKeyId = await jose.calculateJwkThumbprint(
  await jose.exportJWK(opKeyPair.publicKey),
  'sha256'
);

// Create ICT:
const ict = await new SignICT()
  .setProtectedHeader({
    typ: 'jwt+ict',
    alg: 'RS384',
    kid: opKeyId,
  })
  .setIssuer(opBaseUrl)
  .setSubject(subject)
  .setAudience(clientId) // optional
  .setIssuedAt(now)
  .setExpirationTime(now + 3600)
  .setJti(NonceGenerators.base64(16).generate())
  .setConfirmation(popTokenResult.protectedHeader.jwk)
  .setContext(context)
  .sign(opKeyPair.privateKey);

// Prepare Authenticating Party:
const apClientId = 'myauthenticatingparty';
const authenticatingUser = 'authenticatinguser';

// Create E2E PoP Token:
const e2ePoPToken = await new SignE2EPoPToken()
  .setProtectedHeader({
    typ: 'jwt+e2epop',
    alg: 'ES384',
    jkt: await jose.calculateJwkThumbprint(
      await jose.exportJWK(clientKeyPair.publicKey),
      'sha256',
    ),
  })
  .setIssuer(clientId)
  .setSubject(subject)
  .setAudience([apClientId, authenticatingUser])
  .setIssuedAt(now)
  .setExpirationTime(now + 300)
  .setJti(NonceGenerators.base64(16).generate())
  .sign(clientKeyPair.privateKey);

// Verify ICT:
const ictResult = await ictVerify(ict, opKeyPair.publicKey, {
  audience: clientId, // optional
  issuer: opBaseUrl,
  maxTokenAge: 3600,
  requiredContext: context,
  subject: subject,
});

// Verify E2E PoP Token:
const e2ePoPResult = await e2ePoPTokenVerify(
  e2ePoPToken,
  await jose.importJWK(ictResult.payload.cnf.jwk),
  {
    audience: [apClientId, authenticatingUser], // Must fulfill all
    issuer: ictResult.payload.aud,
    maxTokenAge: 300,
    subject: ictResult.payload.sub,
  }
);

console.log(`Successfully identified user "${e2ePoPResult.payload.sub}@${ictResult.payload.iss}"!`);
