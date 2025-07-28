import { createHash, randomBytes, timingSafeEqual } from 'crypto';
import { InvalidRequestError, InvalidScopeError } from './errors';
import { Client, OAuth2Request } from './types';

/**
 * Generates a cryptographically strong random string.
 * Compliant with RFC 7636 for PKCE code verifiers.
 */
export function generateSecureRandomString(length: number): string {
  return randomBytes(Math.ceil(length / 2))
    .toString('hex')
    .slice(0, length);
}

/**
 * Creates a SHA256 hash and encodes it in Base64 URL-safe format.
 * Used for PKCE S256 code challenge verification.
 */
export function createS256Challenge(verifier: string): string {
  return createHash('sha256')
    .update(verifier)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Hashes a client secret using SHA-256 with a salt.
 * Provides protection against rainbow table attacks.
 */
export function hashClientSecret(secret: string, salt?: string): { hashedSecret: string; salt: string } {
  const secretSalt = salt || randomBytes(32).toString('hex');
  const hashedSecret = createHash('sha256')
    .update(secret + secretSalt)
    .digest('hex');

  return { hashedSecret: secretSalt + ':' + hashedSecret, salt: secretSalt };
}

/**
 * Verifies a client secret against a hashed secret using timing-safe comparison.
 * Prevents timing attacks while maintaining backward compatibility.
 */
export function verifyClientSecret(plainSecret: string, hashedSecret: string): boolean {
  try {
    const [salt, hash] = hashedSecret.split(':');
    if (!salt || !hash) {
      // Fallback: if no salt format detected, assume plain text comparison (for backward compatibility)
      // In production, this should log a warning to migrate to hashed secrets
      return timingSafeEqual(Buffer.from(plainSecret), Buffer.from(hashedSecret));
    }

    const { hashedSecret: computedHash } = hashClientSecret(plainSecret, salt);
    const [, computedHashOnly] = computedHash.split(':');

    return timingSafeEqual(Buffer.from(hash), Buffer.from(computedHashOnly));
  } catch (error) {
    return false;
  }
}

/**
 * Validates PKCE code verifier length and character set according to RFC 7636.
 * Ensures the code verifier meets security requirements.
 */
export function validateCodeVerifier(codeVerifier: string, minLength: number = 43, maxLength: number = 128): boolean {
  if (!codeVerifier) {
    throw new InvalidRequestError('Missing code_verifier parameter');
  }

  if (codeVerifier.length < minLength) {
    throw new InvalidRequestError(`code_verifier too short. Minimum length is ${minLength} characters`);
  }

  if (codeVerifier.length > maxLength) {
    throw new InvalidRequestError(`code_verifier too long. Maximum length is ${maxLength} characters`);
  }

  // Validate character set: [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
  const validChars = /^[A-Za-z0-9\-._~]+$/;
  if (!validChars.test(codeVerifier)) {
    throw new InvalidRequestError('code_verifier contains invalid characters. Only [A-Za-z0-9-._~] are allowed');
  }

  return true;
}

/**
 * Validates a PKCE code challenge against a code verifier.
 * Supports both 'plain' and 'S256' challenge methods.
 */
export function validatePkceChallenge(
  codeVerifier: string,
  codeChallenge: string,
  codeChallengeMethod: 'plain' | 'S256',
): boolean {
  if (codeChallengeMethod === 'plain') {
    return codeChallenge === codeVerifier;
  } else if (codeChallengeMethod === 'S256') {
    const hashedCodeVerifier = createS256Challenge(codeVerifier);
    return codeChallenge === hashedCodeVerifier;
  }

  throw new InvalidRequestError('Unsupported code_challenge_method');
}

/**
 * Parses a space-delimited scope string into an array of individual scopes.
 * Filters out empty strings and normalizes the input.
 */
export function parseScopes(scopeString: string | undefined): string[] {
  if (!scopeString) {
    return [];
  }

  return scopeString.split(' ').filter((scope) => scope.length > 0);
}

/**
 * Validates that all requested scopes are supported by the server.
 * Throws an error if any scope is not in the predefined list.
 */
export function validateScopeSupport(requestedScopes: string[], predefinedScopes: string[]): void {
  for (const scope of requestedScopes) {
    if (!predefinedScopes.includes(scope)) {
      throw new InvalidScopeError(`Invalid scope: ${scope}`);
    }
  }
}

/**
 * Validates that the client is allowed to request the specified scopes.
 * Throws an error if the client doesn't have permission for any scope.
 */
export function validateClientScopePermission(requestedScopes: string[], client: Client): void {
  for (const scope of requestedScopes) {
    if (!client.scopes.includes(scope)) {
      throw new InvalidScopeError(`Client not allowed to request scope: ${scope}`);
    }
  }
}

/**
 * Validates the requested scopes against predefined and client-specific allowed scopes.
 * Returns the validated, space-delimited scope string.
 */
export function validateScope(requestedScope: string | undefined, predefinedScopes: string[], client: Client): string {
  if (!requestedScope) {
    return '';
  }
  const scopes = parseScopes(requestedScope);

  // Validate all scopes are supported by the server
  validateScopeSupport(scopes, predefinedScopes);

  // Validate the client is allowed to request these scopes
  validateClientScopePermission(scopes, client);

  return scopes.join(' ');
}

/**
 * Validates a redirect URI against a client's registered URIs.
 * Handles the case where no redirect URI is provided but the client has exactly one registered.
 */
export function validateRedirectUri(client: { redirectUris: string[] }, redirectUri?: string): string {
  if (redirectUri) {
    if (!client.redirectUris.includes(redirectUri)) {
      throw new InvalidRequestError('Invalid redirect_uri');
    }
    return redirectUri;
  } else if (client.redirectUris.length === 1) {
    return client.redirectUris[0];
  } else {
    throw new InvalidRequestError('Missing redirect_uri parameter, and client has multiple registered redirect URIs');
  }
}

/**
 * Parses a URL-encoded body from an OAuth2Request.
 * Converts form data into a record for easy access.
 */
function parseUrlEncodedBody(request: OAuth2Request & { body: string }): Record<string, any> {
  const body = request.body as string;
  const params = new URLSearchParams(body);
  const parsedBody: Record<string, any> = {};

  for (const [key, value] of params.entries()) {
    parsedBody[key] = value;
  }

  return parsedBody;
}

/**
 * Takes an OAuth2Request and returns the parsed body as a record.
 * Handles both JSON and form-urlencoded content types.
 *
 * @see RFC 6749, Section 4.1.3 Access Token Request
 * @see RFC 6749, Appendix B Use of application/x-www-form-urlencoded Media Type
 */
export function parseRequestBody(request: OAuth2Request): Record<string, any> {
  const contentType = request.headers['Content-Type'] || request.headers['content-type'] || '';

  // Handle application/x-www-form-urlencoded
  if (contentType.includes('application/x-www-form-urlencoded') && typeof request.body === 'string') {
    return parseUrlEncodedBody(request as OAuth2Request & { body: string });
  }

  // Handle application/json
  if (contentType.includes('application/json')) {
    return typeof request.body === 'string' ? JSON.parse(request.body) : request.body!;
  }

  // If the content type is not recognized, try to parse as URL-encoded first, then as JSON
  if (typeof request.body === 'string') {
    // Try URL-encoded parsing first (most common for OAuth)
    try {
      const mockRequest = { ...request, body: request.body } as OAuth2Request & { body: string };
      return parseUrlEncodedBody(mockRequest);
    } catch {
      // Fall back to JSON parsing
      try {
        return JSON.parse(request.body);
      } catch {
        // If both fail, return an empty object
        return {};
      }
    }
  }
  return request.body!;
}

/**
 * Generates a cryptographically strong random string.
 * Uses Node.js crypto module for secure random generation.
 */
export function generateRandomString(length: number): string {
  const { randomBytes } = require('crypto');
  return randomBytes(Math.ceil(length / 2))
    .toString('hex')
    .slice(0, length);
}

/**
 * Extracts client credentials from Basic authentication header.
 * Returns null if no Basic auth header is present.
 */
export function extractBasicAuthCredentials(authHeader?: string): { clientId: string; clientSecret: string } | null {
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return null;
  }

  const credentials = Buffer.from(authHeader.substring(6), 'base64').toString().split(':');
  return {
    clientId: credentials[0],
    clientSecret: credentials[1],
  };
}
