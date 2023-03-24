import * as crypto from 'crypto';
import { SignJWT } from 'jose';
import { encodeBase64url } from '@jonasprimbs/byte-array-converter';

import { IctRequestTokenHeader } from './ict-request-token-header.interface';
import { IctRequestTokenPayload } from './ict-request-token-payload.interface';
import { NonceGenerator, NonceGenerators } from '../nonce-generators';
import { JwsSignatureAlgorithm } from '../types';

export class IctRequestToken {

  /**
   * The public key to prove possession of.
   */
  private publicKey?: crypto.webcrypto.CryptoKey;

  /**
   * The signature as Base64URL encoded string.
   */
  private signature?: string;

  /**
   * The claims of the payload.
   */
  private readonly claims: Partial<IctRequestTokenPayload> = {};

  /**
   * The JWT object for the ICT Request Token.
   */
  private readonly jwt: SignJWT = new SignJWT(this.claims);

  /**
   * Sets the public key for the ICT Request Token.
   * @param publicKey Public key of the ICT Request Token.
   * @returns The updated ICT Request Token instance.
   */
  setPublicKey(publicKey: crypto.webcrypto.CryptoKey): IctRequestToken {
    // Verify that provided key is a public key.
    if (publicKey.type !== 'public') {
      throw 'Provided public key is not of type "public"!';
    }
    // Verify that provided key is meant for signing.
    if (publicKey.usages.indexOf('verify') === -1) {
      throw 'Provided public key has no usage "verify"!';
    }
    // Verify that provided key is extractable.
    if (!publicKey.extractable) {
      throw 'Provided public key is not extactable!';
    }
    // Verify that provided key has a sufficient algorithm name.
    switch (publicKey.algorithm.name) {
    case 'ECDSA':
      // ES256 / ES384 / ES512.
      break;
    case 'RSA-PSS':
      // PS256 / PS384 / PS512.
      break;
    case 'RSASSA-PKCS1-v1_5':
      // RS256 / RS384 / RS512.
      break;
    default:
      throw `Provided public key has an unsupported signing algorithm "${publicKey.algorithm.name}"!`;
    }

    // Clear outdated signature.
    this.signature = undefined;

    // Set public key.
    this.publicKey = publicKey;

    return this;
  }

  /**
   * Indicates whether a public key is provided.
   * @returns true = has a public key; false = has no public key.
   */
  hasPublicKey(): boolean {
    return this.publicKey instanceof crypto.webcrypto.CryptoKey;
  }

  /**
   * Gets the set public key.
   * @returns The public key.
   */
  getPublicKey(): crypto.webcrypto.CryptoKey | undefined {
    return this.publicKey;
  }

  /**
   * Exports the public key.
   * @param format Format of the exported public key.
   * @returns The exported public key.
   */
  async exportPublicKey<T extends KeyExportFormat>(format: T): Promise<KeyExportType<T> | undefined> {
    if (this.publicKey === undefined) {
      return undefined;
    }

    if (format === 'jwk') {
      return await crypto.subtle.exportKey(format, this.publicKey) as KeyExportType<T>;
    } else {
      return await crypto.subtle.exportKey(format, this.publicKey) as KeyExportType<T>;
    }
  }

  /**
   * Sets the "sub" (Subject) claim.
   * @param subject Subject of the ICT Request Token, e.g., the user's identifier ("sub" claim in the ID Token).
   * @returns The updated ICT Request Token instance.
   */
  setSubject(subject: string): IctRequestToken {
    // Clear outdated signature.
    this.signature = undefined;

    // Set the subject ("sub") claim.
    this.jwt.setSubject(subject);

    return this;
  }

  /**
   * Indicates whether the subject is provided.
   * @returns true = has subject; false = has no subject.
   */
  hasSubject(): boolean {
    return !!this.claims.sub;
  }

  /**
   * Gets the subject of the ICT Request Token.
   * @returns The provided subject.
   */
  getSubject(): string | undefined {
    return this.claims.sub;
  }

  /**
   * Sets the "aud" (Audience) claim.
   * @param audience Audience(s) of the ICT Request Token, e.g., the OpenID Provider's identifier ("iss" claim in the ID Token).
   * @returns The updated ICT Request Token instance.
   */
  setAudience(audience: string | string[]): IctRequestToken {
    // Clear outdated signature.
    this.signature = undefined;

    // Set the audience ("aud") claim.
    this.jwt.setAudience(audience);

    return this;
  }

  /**
   * Indicates whether the audience is provided.
   * @returns true = has an audience; false = has no audience.
   */
  hasAudience(): boolean {
    if (!this.claims.aud) {
      return false;
    } else if (this.claims.aud instanceof Array) {
      return this.claims.aud.length > 0;
    } else {
      return !!this.claims.aud;
    }
  }

  /**
   * Gets the audience of the ICT Request Token.
   * @returns The provided audience.
   */
  getAudience(): string | string[] | undefined {
    return this.claims.aud;
  }

  /**
   * Sets the "iss" (Issuer) claim.
   * @param issuer Issuer of the ICT Request Token, e.g., the Client's identifier ("aud" claim in the ID Token).
   * @returns The updated ICT Request Token instance.
   */
  setIssuer(issuer: string): IctRequestToken {
    // Clear outdated signature.
    this.signature = undefined;

    // Set the issuer ("iss") claim.
    this.jwt.setIssuer(issuer);

    return this;
  }

  /**
   * Indicates whether the issuer is provided.
   * @returns true = has an issuer; false = has no issuer.
   */
  hasIssuer(): boolean {
    return !!this.claims.iss;
  }

  /**
   * Gets the issuer of the ICT Request Token.
   * @returns The provided issuer.
   */
  getIssuer(): string | undefined {
    return this.claims.iss;
  }

  /**
   * Sets the "jti" (JSON Web Token ID) claim.
   * @param jwtId JSON Web Token ID of the ICT Request Token. Typically a registered random string. Default is a newly generated UUID.
   * @returns The updated ICT Request Token instance.
   */
  setJti(jwtId: string = NonceGenerators.uuid().generate()): IctRequestToken {
    // Clear outdated signature.
    this.signature = undefined;

    // Set the JWT ID ("jti") claim.
    this.jwt.setJti(jwtId);

    return this;
  }

  /**
   * Indicates whether a JWT ID is provided.
   * @returns true = has a JWT ID; false = has no JWT ID.
   */
  hasJti(): boolean {
    return !!this.claims.jti;
  }

  /**
   * Gets the JWT ID of the ICT Request Token.
   * @returns The provided JWT ID.
   */
  getJti(): string | undefined {
    return this.claims.jti;
  }

  /**
   * Sets the "nonce" (Nonce) claim.
   * @param nonce Nonce of the ICT Request Token. Typically a random string.
   * @returns The updated ICT Request Token instance.
   */
  setNonce(nonce: string): IctRequestToken {
    // Validate input value.
    if (!nonce) {
      throw 'Nonce value must not be an empty string!';
    }

    // Clear outdated signature.
    this.signature = undefined;

    // Set the Nonce ("nonce") claim.
    this.claims.nonce = nonce;

    return this;
  }

  /**
   * Indicates whether the nonce is provided.
   * @returns true = has a nonce; false = has no nonce.
   */
  hasNonce(): boolean {
    return !!this.claims.nonce;
  }

  /**
   * Gets the nonce of the ICT Request Token.
   * @returns The provided nonce.
   */
  getNonce(): string | undefined {
    return this.claims.nonce;
  }

  /**
   * Generates and sets the "nonce" (Nonce) claim.
   * @param nonceGenerator Nonce generator instance. Default is UUID nonce generator.
   * @returns The updated ICT Request Token instance.
   */
  generateNonce(nonceGenerator: NonceGenerator = NonceGenerators.uuid()): IctRequestToken {
    // Generate a nonce with the provided generator.
    const nonce = nonceGenerator.generate();

    // Set the nonce and return result.
    return this.setNonce(nonce);
  }

  /**
   * Sets the "iat" (Issued at) claim.
   * @param issuedAt Issued at time as Date or as numbered unix timestamp with seconds precision. Default is current timestamp.
   * @returns The updated ICT Request Token instance.
   */
  setIssuedAt(issuedAt?: number | Date): IctRequestToken {
    // Clear outdated signature.
    this.signature = undefined;

    if (issuedAt instanceof Date) {
      // Convert provided issued at date to UTC unix timestamp.
      const issuedAtnumber = Math.floor(issuedAt.getTime() / 1000);
      // Set UTC unix timestamp to issued at time.
      this.jwt.setIssuedAt(issuedAtnumber);
    } else {
      // Set provided UTC unix timestamp to issued at time.
      this.jwt.setIssuedAt(issuedAt);
    }

    return this;
  }

  /**
   * Indicates whether the issued at time is provided.
   * @returns true = has an issued at time; false = has no issued at time.
   */
  hasIssuedAt(): boolean {
    return !!this.claims.iat;
  }

  /**
   * Gets the issued at time of the ICT Request Token as unix timestamp with seconds precision.
   * @returns The provided issued at time as unix timestamp with seconds precision.
   */
  getIssuedAt(): number | undefined {
    return this.claims.iat;
  }

  /**
   * Gets the issued at time of the ICT Request Token as a date object.
   * @returns The provided issued at time as date object.
   */
  getIssuedAtDate(): Date | undefined {
    if (!this.claims.iat) {
      return undefined;
    } else {
      return new Date(this.claims.iat * 1000);
    }
  }

  /**
   * Sets the "nbf" (Not before) claim.
   * @param notBefore Not before time as Date or as numbered unix timestamp with second precision. Default is issued at time if defined, otherwise current timestamp.
   * @returns The updated ICT Request Token instance.
   */
  setNotBefore(notBefore?: number | Date): IctRequestToken {
    // Clear outdated signature.
    this.signature = undefined;

    if (notBefore === undefined) {
      // Set issued at date if defined, otherwise current unix timestamp with seconds precision.
      this.jwt.setNotBefore(this.getIssuedAt() ?? Math.round(Date.now() / 1000));
    } else if (notBefore instanceof Date) {
      // Convert provided not before date to UTC unix timestamp.
      const notBeforenumber = Math.floor(notBefore.getTime() / 1000);
      // Set UTC unix timestamp to not before time.
      this.jwt.setNotBefore(notBeforenumber);
    } else {
      // Set provided UTC unix timestamp to not before time.
      this.jwt.setNotBefore(notBefore);
    }

    return this;
  }

  /**
   * Indicates whether the not before time is provided.
   * @returns true = has a not before time; false = has no not before time.
   */
  hasNotBefore(): boolean {
    return !!this.claims.nbf;
  }

  /**
   * Gets the not before time of the ICT Request Token as unix timestamp with seconds precision.
   * @returns The provided not before time as unix timestamp with seconds precision.
   */
  getNotBefore(): number | undefined {
    return this.claims.nbf;
  }

  /**
   * Gets the not before time of the ICT Request Token as a date object.
   * @returns The provided not before time as date object.
   */
  getNotBeforeDate(): Date | undefined {
    if (!this.claims.nbf) {
      return undefined;
    } else {
      return new Date(this.claims.nbf * 1000);
    }
  }

  /**
   * Sets the "exp" (Expiration time) claim.
   * @param expirationTime Expiration time as Date or as numbered unix timestamp with second precision.
   * @returns The updated ICT Request Token instance.
   */
  setExpirationTime(expirationTime: number | Date): IctRequestToken {
    // Clear outdated signature.
    this.signature = undefined;

    if (expirationTime instanceof Date) {
      // Convert provided expiration time to UTC unix timestamp.
      const expirationTimenumber = Math.floor(expirationTime.getTime() / 1000);
      // Set UTC unix timestamp to expiration time.
      this.jwt.setExpirationTime(expirationTimenumber);
    } else {
      // Set provided UTC unix timestamp to expiration time.
      this.jwt.setNotBefore(expirationTime);
    }

    return this;
  }

  /**
   * Indicates whether the expiration time is provided.
   * @returns true = has an expiration time; false = has no expiration time.
   */
  hasExpirationTime(): boolean {
    return !!this.claims.exp;
  }

  /**
   * Gets the expiration time of the ICT Request Token as unix timestamp with seconds precision.
   * @returns The provided expiration time as unix timestamp with seconds precision.
   */
  getExpirationTime(): number | undefined {
    return this.claims.exp;
  }

  /**
   * Gets the expiration time of the ICT Request Token as a date object.
   * @returns The provided expiration time as date object.
   */
  getExpirationTimeDate(): Date | undefined {
    if (!this.claims.exp) {
      return undefined;
    } else {
      return new Date(this.claims.exp * 1000);
    }
  }

  /**
   * Sets the "token_lifetime" (desired lifetime of the ID Certification Token) claim.
   * @param tokenLifetime Desired lifetime of the requested ID Certification Token.
   * @returns The updated ICT Request Token instance.
   */
  setTokenLifetime(tokenLifetime: number): IctRequestToken {
    // Validate input value.
    if (tokenLifetime < 0) {
      throw 'Negative token lifetime not allowed!';
    }
    if (!Number.isInteger(tokenLifetime)) {
      throw 'Token lifetime must be an integer!';
    }

    // Clear outdated signature.
    this.signature = undefined;

    // Set the token lifetime ("token_lifetime") claim.
    this.claims.token_lifetime = tokenLifetime;

    return this;
  }

  /**
   * Indicates whether the token lifetime is provided.
   * @returns true = has a token lifetime; false = has no token lifetime.
   */
  hasTokenLifetime(): boolean {
    return !!this.claims.token_lifetime;
  }

  /**
   * Gets the token lifetime of the ICT Request Token.
   * @returns The provided token lifetime.
   */
  getTokenLifetime(): number | undefined {
    return this.claims.token_lifetime;
  }

  /**
   * Sets the "token_nonce" (desired nonce of the ID Certification Token) claim.
   * @param tokenNonce Desired token nonce of the requested ID Certification Token.
   * @returns The updated ICT Request Token instance.
   */
  setTokenNonce(tokenNonce: string): IctRequestToken {
    // Validate input value.
    if (!tokenNonce) {
      throw 'Token nonce must not be an empty string!';
    }

    // Clear outdated signature.
    this.signature = undefined;

    // Set the token nonce ("token_nonce") claim.
    this.claims.token_nonce = tokenNonce;

    return this;
  }

  /**
   * Generates and sets the "token_nonce" (Token nonce) claim.
   * @param nonceGenerator Nonce generator instance. Default is UUID nonce generator.
   * @returns The updated ICT Request Token instance.
   */
  generateTokenNonce(nonceGenerator: NonceGenerator = NonceGenerators.uuid()): IctRequestToken {
    // Generate a token nonce with the provided generator.
    const tokenNonce = nonceGenerator.generate();
    
    // Set the token nonce and return the result.
    return this.setTokenNonce(tokenNonce);
  }

  /**
   * Indicates whether the token nonce is provided.
   * @returns true = has a token nonce; false = has no token nonce.
   */
  hasTokenNonce(): boolean {
    return !!this.claims.token_nonce;
  }

  /**
   * Gets the token nonce of the ICT Request Token.
   * @returns The provided token nonce.
   */
  getTokenNonce(): string | undefined {
    return this.claims.token_nonce;
  }

  /**
   * Sets the "token_claims" (desired identity claims for the ID Certification Token) claim.
   * @param claims Enumeration of desired identity claims for the requested ID Certification Token. Duplicates and empty strings will be omitted. If no claim is provided, the call will be ignored.
   * @returns The updated ICT Request Token instance.
   */
  setTokenClaims(...claims: string[]): IctRequestToken {
    // Verify that string is not empty.
    if (claims.length === 0) {
      return this;
    }

    // Filter empty strings and duplicates.
    const filteredClaims = [...new Set(claims.filter(c => !!c))];

    // Reduce array to space-separated strings.
    const claimsstring = filteredClaims.join(' ');

    // Clear outdated signature.
    this.signature = undefined;

    // Set the token claims ("token_claims") value.
    this.claims.token_claims = claimsstring;

    return this;
  }

  /**
   * Indicates whether the token claims are provided.
   * @returns true = has token claims; false = has no token claims.
   */
  hasTokenClaims(): boolean {
    return !!this.claims.token_claims;
  }

  /**
   * Gets the token claims of the ICT Request Token.
   * @returns The provided token claims.
   */
  getTokenClaims(): string[] | undefined {
    return this.claims.token_claims?.split(' ');
  }

  /**
   * Gets the ICT Request Token header as object.
   * @returns The ICT Request Token header as object.
   */
  async getHeaderObject(): Promise<IctRequestTokenHeader> {
    if (!this.publicKey) {
      throw 'Public key missing!';
    }

    return {
      typ: 'JWT+IRT',
      alg: getSufficientSignatureAlgorithm(this.publicKey),
      jwk: await crypto.subtle.exportKey('jwk', this.publicKey),
    };
  }

  /**
   * Gets the ICT Request Token header as JSON-serialized and Base64URL encoded string.
   * @returns The ICT Request Token header as JSON-serialized and Base64URL encoded string.
   */
  async getHeaderString(): Promise<string> {
    const obj = await this.getHeaderObject();
    return objectToBase64Url(obj);
  }

  /**
   * Gets the ICT Request Token payload as object.
   * @returns The ICT Request Token payload as object.
   */
  getPayloadObject(): IctRequestTokenPayload {
    // Verify that issuer is set.
    if (!this.claims.iss) {
      throw 'No issuer set!';
    }
    // Verify that subject is set.
    if (!this.claims.sub) {
      throw 'No subject set!';
    }
    // Verify that audience is set.
    if (!this.claims.aud) {
      throw 'No audience set!';
    }
    // Verify that date is set.
    if (!this.claims.iat) {
      throw 'No issued at date set!';
    }
    // Verify that expiration date is set.
    if (!this.claims.exp) {
      throw 'No expiration date set!';
    }

    // Return payoad.
    return {
      iss: this.claims.iss,
      sub: this.claims.sub,
      aud: this.claims.aud,
      jti: this.claims.jti,
      nonce: this.claims.nonce,
      iat: this.claims.iat,
      nbf: this.claims.nbf,
      exp: this.claims.exp,
      token_lifetime: this.claims.token_lifetime,
      token_nonce: this.claims.token_nonce,
      token_claims: this.claims.token_claims,
    };
  }

  /**
   * Gets the ICT Request Token payload as JSON-serialized and Base64URL encoded string.
   * @returns The ICT Request Token payload as JSON-serialized and Base64URL encoded string.
   */
  getPayloadString(): string {
    const obj = this.getPayloadObject();
    return objectToBase64Url(obj);
  }

  /**
   * Gets the ICT Request Token header and payload, dot-separated as JSON-serialized and Base64URL encoded string.
   * @returns The ICT Request Token header and payload, dot-separated as JSON-serialized and Base64URL encoded string.
   */
  async getHeaderAndPayloadString(): Promise<string> {
    const header = await this.getHeaderString();
    const payload = this.getPayloadString();
    return `${header}.${payload}`;
  }

  /**
   * Signs an ICT Request Token.
   * @param privateKey The private key to sign the ICT Request Token with.
   * @returns Signed ICT Request Token.
   */
  async sign(privateKey: crypto.webcrypto.CryptoKey): Promise<IctRequestToken> {
    // Verify that provided key is a public key.
    if (privateKey.type !== 'private') {
      throw 'Provided private key is not of type "private"!';
    }
    // Verify that provided key is meant for signing.
    if (privateKey.usages.indexOf('sign') === -1) {
      throw 'Provided private key has no usage "sign"!';
    }
    // Verify that the public key is provided.
    if (!this.publicKey) {
      throw 'No public key provided!';
    }
    // Verify that provided key has a sufficient algorithm name.
    if (privateKey.algorithm.name !== this.publicKey.algorithm.name) {
      throw `Provided private key signing algorithm "${privateKey.algorithm.name}" does not match the set public key signing algorithm "${this.publicKey.algorithm.name}"!`;
    }

    // TODO: implement signing of the JWT.
    const jwt = await this.jwt.sign(privateKey);
    this.signature = jwt.split('.')[2];

    return this;
  }

  /**
   * Gets the signature as Base64URL encoded string.
   * @returns The signature as Base64URL encoded string.
   */
  getSignatureString(): string {
    if (!this.signature) {
      throw 'Token not signed!';
    }

    return this.signature;
  }

  /**
   * Gets the ICT Request Token as JWT string.
   * @returns The ICT Request Token as JWT string.
   */
  async getTokenString(): Promise<string> {
    if (!this.signature) {
      throw 'Token not signed!';
    }

    // Generate header and payload string to sign.
    const headerAndPayloadString = await this.getHeaderAndPayloadString();

    return `${headerAndPayloadString}.${this.signature}`;
  }
}

/**
 * Output format of an exported key.
 */
export type KeyExportFormat = 'jwk' | 'pkcs8' | 'raw' | 'spki';

/**
 * The data type of an exported key depending on the key export format.
 */
export type KeyExportType<T extends KeyExportFormat> = T extends 'jwk' ? crypto.webcrypto.JsonWebKey : ArrayBuffer;

/**
 * Converts a string to an UTF8-encoded byte array.
 * @param str String to convert.
 * @returns The UTF8-encoded string.
 */
function stringToUtf8Array(str: string): Uint8Array {
  const encoder = new TextEncoder();
  return encoder.encode(str);
}

/**
 * Serializes an object with JSON and encodes the string Base64URL.
 * @param obj Object to convert.
 * @returns JSON-serialized and Base64URL encoded object as string.
 */
function objectToBase64Url(obj: object): string {
  const json = JSON.stringify(obj);
  const utf8 = stringToUtf8Array(json);
  return encodeBase64url(utf8);
}

/**
 * Gets a sufficient signing algorithm for a provided asymmetric key.
 * @param key An asymmetric key.
 * @returns A sufficient signing algorithm.
 */
function getSufficientSignatureAlgorithm(key: crypto.webcrypto.CryptoKey): JwsSignatureAlgorithm {
  switch (key.algorithm.name) {
  // Elliptic Curve: (ES256 / ES384 / ES512)
  case 'ECDSA': {
    const esAlgorithm = key.algorithm as crypto.webcrypto.EcKeyAlgorithm;
    switch (esAlgorithm.namedCurve) {
    case 'P-256':
      return 'ES256';
    case 'P-384':
      return 'ES384';
    case 'P-521':
      return 'ES512';
    default:
      throw `Unsupported curve name ${esAlgorithm.namedCurve}`;
    }
  }
  // RSA Probablistic Signing Scheme: (PS256 / PS384 / PS512)
  case 'RSA-PSS': {
    const psAlgorithm = key.algorithm as crypto.webcrypto.RsaHashedKeyAlgorithm;
    switch (psAlgorithm.hash.name) {
    case 'SHA-256':
      return 'RS256';
    case 'SHA-384':
      return 'RS384';
    case 'SHA-512':
      return 'RS512';
    default:
      throw `Unsupported hash algorithm name ${psAlgorithm.hash}`;
    }
  }
  // RSA Public Key Cryptography Standard: (RS256 / RS384 / RS512)
  case 'RSASSA-PKCS-v1_5': {
    const rsAlgorithm = key.algorithm as crypto.webcrypto.RsaHashedKeyAlgorithm;
    switch (rsAlgorithm.hash.name) {
    case 'SHA-256':
      return 'RS256';
    case 'SHA-384':
      return 'RS384';
    case 'SHA-512':
      return 'RS512';
    default:
      throw `Unsupported hash algorithm name ${rsAlgorithm.hash}`;
    }
  }
  default:
    throw `Unsupported algorithm name ${key.algorithm.name}`;
  }
}
