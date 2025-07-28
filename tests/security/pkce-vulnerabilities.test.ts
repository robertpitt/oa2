/**
 * PKCE Security Vulnerability Tests
 *
 * Tests for Proof Key for Code Exchange (PKCE) vulnerabilities according to RFC 7636.
 * These tests ensure our implementation is resistant to common PKCE attack vectors.
 */

import { createOAuth2Server } from '../../src';
import { authorizationCodeGrant } from '../../src/grants';
import { InMemoryStorageAdapter } from '../mocks/storage';
import { OAuth2Request, Client } from '../../src/types';
import { InvalidRequestError, InvalidGrantError } from '../../src/errors';

describe('PKCE Security Vulnerabilities', () => {
  let server: any;
  let storage: any;
  let client: Client;

  beforeEach(async () => {
    storage = new InMemoryStorageAdapter();
    server = createOAuth2Server({
      storage,
      grants: [authorizationCodeGrant()],
      predefinedScopes: ['read', 'write', 'offline_access'],
    });

    client = {
      id: 'test_client',
      secret: 'test_secret',
      redirectUris: ['https://client.example.com/cb'],
      allowedGrants: ['authorization_code'],
      scopes: ['read', 'write', 'offline_access'],
    };

    await storage.saveClient(client);
  });

  describe('Code Verifier Length Attacks', () => {
    it('should reject extremely short code verifiers (< 43 characters)', async () => {
      const shortVerifier = 'short'; // 5 characters - way too short

      // First get an authorization code
      await storage.saveAuthorizationCode({
        code: 'test_code',
        expiresAt: new Date(Date.now() + 60000),
        redirectUri: client.redirectUris[0],
        scope: 'read',
        clientId: client.id,
        userId: 'user123',
        codeChallenge: 'challenge',
        codeChallengeMethod: 'plain',
      });

      const request: OAuth2Request = {
        path: '/token',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString('base64')}`,
        },
        query: {},
        body: `grant_type=authorization_code&code=test_code&redirect_uri=${client.redirectUris[0]}&code_verifier=${shortVerifier}`,
        cookies: {},
      };

      await expect(server.token(request)).rejects.toThrow(InvalidRequestError);
      await expect(server.token(request)).rejects.toThrow('code_verifier too short');
    });

    it('should reject extremely long code verifiers (> 128 characters)', async () => {
      const longVerifier = 'a'.repeat(200); // 200 characters - way too long

      await storage.saveAuthorizationCode({
        code: 'test_code',
        expiresAt: new Date(Date.now() + 60000),
        redirectUri: client.redirectUris[0],
        scope: 'read',
        clientId: client.id,
        userId: 'user123',
        codeChallenge: 'challenge',
        codeChallengeMethod: 'plain',
      });

      const request: OAuth2Request = {
        path: '/token',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString('base64')}`,
        },
        query: {},
        body: `grant_type=authorization_code&code=test_code&redirect_uri=${client.redirectUris[0]}&code_verifier=${longVerifier}`,
        cookies: {},
      };

      await expect(server.token(request)).rejects.toThrow(InvalidRequestError);
      await expect(server.token(request)).rejects.toThrow('code_verifier too long');
    });

    it('should reject code verifiers at boundary lengths (42 characters)', async () => {
      const boundaryVerifier = 'a'.repeat(42); // Exactly 42 characters - should fail

      await storage.saveAuthorizationCode({
        code: 'test_code',
        expiresAt: new Date(Date.now() + 60000),
        redirectUri: client.redirectUris[0],
        scope: 'read',
        clientId: client.id,
        userId: 'user123',
        codeChallenge: 'challenge',
        codeChallengeMethod: 'plain',
      });

      const request: OAuth2Request = {
        path: '/token',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString('base64')}`,
        },
        query: {},
        body: `grant_type=authorization_code&code=test_code&redirect_uri=${client.redirectUris[0]}&code_verifier=${boundaryVerifier}`,
        cookies: {},
      };

      await expect(server.token(request)).rejects.toThrow(InvalidRequestError);
      await expect(server.token(request)).rejects.toThrow('code_verifier too short');
    });
  });

  describe('Code Verifier Character Set Attacks', () => {
    it('should reject code verifiers with invalid characters (spaces)', async () => {
      const invalidVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk invalid';

      await storage.saveAuthorizationCode({
        code: 'test_code',
        expiresAt: new Date(Date.now() + 60000),
        redirectUri: client.redirectUris[0],
        scope: 'read',
        clientId: client.id,
        userId: 'user123',
        codeChallenge: 'challenge',
        codeChallengeMethod: 'plain',
      });

      const request: OAuth2Request = {
        path: '/token',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString('base64')}`,
        },
        query: {},
        body: `grant_type=authorization_code&code=test_code&redirect_uri=${client.redirectUris[0]}&code_verifier=${invalidVerifier}`,
        cookies: {},
      };

      await expect(server.token(request)).rejects.toThrow(InvalidRequestError);
      await expect(server.token(request)).rejects.toThrow('invalid characters');
    });

    it('should reject code verifiers with special characters (not in allowed set)', async () => {
      const invalidVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk@#$';

      await storage.saveAuthorizationCode({
        code: 'test_code',
        expiresAt: new Date(Date.now() + 60000),
        redirectUri: client.redirectUris[0],
        scope: 'read',
        clientId: client.id,
        userId: 'user123',
        codeChallenge: 'challenge',
        codeChallengeMethod: 'plain',
      });

      const request: OAuth2Request = {
        path: '/token',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString('base64')}`,
        },
        query: {},
        body: `grant_type=authorization_code&code=test_code&redirect_uri=${client.redirectUris[0]}&code_verifier=${invalidVerifier}`,
        cookies: {},
      };

      await expect(server.token(request)).rejects.toThrow(InvalidRequestError);
      await expect(server.token(request)).rejects.toThrow('invalid characters');
    });

    it('should accept code verifiers with all valid characters', async () => {
      const validVerifier = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';

      await storage.saveAuthorizationCode({
        code: 'test_code',
        expiresAt: new Date(Date.now() + 60000),
        redirectUri: client.redirectUris[0],
        scope: 'read',
        clientId: client.id,
        userId: 'user123',
        codeChallenge: validVerifier, // Plain challenge
        codeChallengeMethod: 'plain',
      });

      const request: OAuth2Request = {
        path: '/token',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString('base64')}`,
        },
        query: {},
        body: `grant_type=authorization_code&code=test_code&redirect_uri=${client.redirectUris[0]}&code_verifier=${validVerifier}`,
        cookies: {},
      };

      const response = await server.token(request);
      expect(response.statusCode).toBe(200);
      expect(response.body).toHaveProperty('access_token');
    });
  });

  describe('Code Challenge Manipulation Attacks', () => {
    it('should reject mismatched plain code challenge and verifier', async () => {
      const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
      const wrongChallenge = 'wrong-challenge-value';

      await storage.saveAuthorizationCode({
        code: 'test_code',
        expiresAt: new Date(Date.now() + 60000),
        redirectUri: client.redirectUris[0],
        scope: 'read',
        clientId: client.id,
        userId: 'user123',
        codeChallenge: wrongChallenge,
        codeChallengeMethod: 'plain',
      });

      const request: OAuth2Request = {
        path: '/token',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString('base64')}`,
        },
        query: {},
        body: `grant_type=authorization_code&code=test_code&redirect_uri=${client.redirectUris[0]}&code_verifier=${verifier}`,
        cookies: {},
      };

      await expect(server.token(request)).rejects.toThrow(InvalidGrantError);
      await expect(server.token(request)).rejects.toThrow('Invalid code_verifier');
    });

    it('should reject mismatched S256 code challenge and verifier', async () => {
      const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
      const wrongChallenge = 'wrong-s256-challenge';

      await storage.saveAuthorizationCode({
        code: 'test_code',
        expiresAt: new Date(Date.now() + 60000),
        redirectUri: client.redirectUris[0],
        scope: 'read',
        clientId: client.id,
        userId: 'user123',
        codeChallenge: wrongChallenge,
        codeChallengeMethod: 'S256',
      });

      const request: OAuth2Request = {
        path: '/token',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString('base64')}`,
        },
        query: {},
        body: `grant_type=authorization_code&code=test_code&redirect_uri=${client.redirectUris[0]}&code_verifier=${verifier}`,
        cookies: {},
      };

      await expect(server.token(request)).rejects.toThrow(InvalidGrantError);
      await expect(server.token(request)).rejects.toThrow('Invalid code_verifier');
    });

    it('should correctly validate S256 code challenges', async () => {
      const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
      const s256Challenge = 'incorrect_challenge_that_should_fail_validation'; // Invalid challenge

      await storage.saveAuthorizationCode({
        code: 'test_code',
        expiresAt: new Date(Date.now() + 60000),
        redirectUri: client.redirectUris[0],
        scope: 'read',
        clientId: client.id,
        userId: 'user123',
        codeChallenge: s256Challenge,
        codeChallengeMethod: 'S256',
      });

      const request: OAuth2Request = {
        path: '/token',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString('base64')}`,
        },
        query: {},
        body: `grant_type=authorization_code&code=test_code&redirect_uri=${client.redirectUris[0]}&code_verifier=${verifier}`,
        cookies: {},
      };

      await expect(server.token(request)).rejects.toThrow(InvalidGrantError);
      await expect(server.token(request)).rejects.toThrow('Invalid code_verifier');
    });
  });

  describe('Missing PKCE Parameters', () => {
    it('should reject token requests without code_verifier', async () => {
      await storage.saveAuthorizationCode({
        code: 'test_code',
        expiresAt: new Date(Date.now() + 60000),
        redirectUri: client.redirectUris[0],
        scope: 'read',
        clientId: client.id,
        userId: 'user123',
        codeChallenge: 'challenge',
        codeChallengeMethod: 'plain',
      });

      const request: OAuth2Request = {
        path: '/token',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString('base64')}`,
        },
        query: {},
        body: `grant_type=authorization_code&code=test_code&redirect_uri=${client.redirectUris[0]}`,
        cookies: {},
      };

      await expect(server.token(request)).rejects.toThrow(InvalidRequestError);
      await expect(server.token(request)).rejects.toThrow('Missing code_verifier');
    });

    it('should reject empty code_verifier', async () => {
      await storage.saveAuthorizationCode({
        code: 'test_code',
        expiresAt: new Date(Date.now() + 60000),
        redirectUri: client.redirectUris[0],
        scope: 'read',
        clientId: client.id,
        userId: 'user123',
        codeChallenge: 'challenge',
        codeChallengeMethod: 'plain',
      });

      const request: OAuth2Request = {
        path: '/token',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString('base64')}`,
        },
        query: {},
        body: `grant_type=authorization_code&code=test_code&redirect_uri=${client.redirectUris[0]}&code_verifier=`,
        cookies: {},
      };

      await expect(server.token(request)).rejects.toThrow(InvalidRequestError);
      await expect(server.token(request)).rejects.toThrow('Missing code_verifier');
    });
  });

  describe('Unsupported Challenge Methods', () => {
    it('should reject unsupported code challenge methods', async () => {
      const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

      await storage.saveAuthorizationCode({
        code: 'test_code',
        expiresAt: new Date(Date.now() + 60000),
        redirectUri: client.redirectUris[0],
        scope: 'read',
        clientId: client.id,
        userId: 'user123',
        codeChallenge: 'challenge',
        codeChallengeMethod: 'MD5' as any, // Invalid method
      });

      const request: OAuth2Request = {
        path: '/token',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString('base64')}`,
        },
        query: {},
        body: `grant_type=authorization_code&code=test_code&redirect_uri=${client.redirectUris[0]}&code_verifier=${verifier}`,
        cookies: {},
      };

      await expect(server.token(request)).rejects.toThrow(InvalidRequestError);
      await expect(server.token(request)).rejects.toThrow('Unsupported code_challenge_method');
    });
  });
});
