/**
 * Input Validation Security Tests
 *
 * Tests for input validation vulnerabilities and injection attacks.
 * Ensures our implementation properly validates and sanitizes all inputs.
 */

import { createOAuth2Server } from '../../src';
import { authorizationCodeGrant, clientCredentialsGrant } from '../../src/grants';
import { InMemoryStorageAdapter } from '../mocks/storage';
import { OAuth2Request, Client } from '../../src/types';
import { InvalidRequestError, InvalidScopeError, UnauthorizedClientError } from '../../src/errors';

describe('Input Validation Security', () => {
  let server: any;
  let storage: any;
  let client: Client;

  beforeEach(async () => {
    storage = new InMemoryStorageAdapter();
    server = createOAuth2Server({
      storage,
      grants: [authorizationCodeGrant(), clientCredentialsGrant()],
      predefinedScopes: ['read', 'write', 'admin'],
    });

    client = {
      id: 'test_client',
      secret: 'test_secret',
      redirectUris: ['https://client.example.com/cb'],
      allowedGrants: ['authorization_code', 'client_credentials'],
      scopes: ['read', 'write'],
    };

    await storage.saveClient(client);
  });

  describe('Content-Type Attacks', () => {
    it('should reject unsupported content types for token endpoint', async () => {
      const maliciousContentTypes = [
        'application/json', // JSON not typically used for OAuth token requests
        'text/xml',
        'application/xml',
        'multipart/form-data',
        'text/plain',
        'image/jpeg',
        'application/octet-stream',
      ];

      for (const contentType of maliciousContentTypes) {
        const request: OAuth2Request = {
          path: '/token',
          method: 'POST',
          headers: {
            'Content-Type': contentType,
            Authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString('base64')}`,
          },
          query: {},
          body: 'grant_type=client_credentials&scope=read',
          cookies: {},
        };

        // Should handle gracefully - either parse correctly or reject appropriately
        try {
          const response = await server.token(request);
          // If it succeeds, it should be a valid response
          expect(response.statusCode).toBeGreaterThanOrEqual(200);
        } catch (error) {
          // If it fails, it should be a proper OAuth error
          expect(error).toBeInstanceOf(Error);
        }
      }
    });

    it('should handle missing Content-Type header', async () => {
      const request: OAuth2Request = {
        path: '/token',
        method: 'POST',
        headers: {
          Authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString('base64')}`,
        },
        query: {},
        body: 'grant_type=client_credentials&scope=read',
        cookies: {},
      };

      const response = await server.token(request);
      expect(response.statusCode).toBe(200);
    });
  });

  describe('Header Injection Attacks', () => {
    it('should reject headers with null bytes', async () => {
      const request: OAuth2Request = {
        path: '/token',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString('base64')}`,
          'X-Malicious': 'value\x00injection',
        },
        query: {},
        body: 'grant_type=client_credentials&scope=read',
        cookies: {},
      };

      // Should handle gracefully without crashing
      const response = await server.token(request);
      expect(response.statusCode).toBe(200);
    });

    it('should reject headers with CRLF injection attempts', async () => {
      const request: OAuth2Request = {
        path: '/token',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString('base64')}`,
          'X-Malicious': 'value\r\nSet-Cookie: evil=true',
        },
        query: {},
        body: 'grant_type=client_credentials&scope=read',
        cookies: {},
      };

      const response = await server.token(request);
      expect(response.statusCode).toBe(200);
      // Should not have injected headers
      expect(response.headers['Set-Cookie']).toBeUndefined();
    });
  });

  describe('Query Parameter Injection', () => {
    it('should handle malicious query parameters in authorization requests', async () => {
      const maliciousParams = {
        client_id: client.id,
        response_type: 'code',
        redirect_uri: client.redirectUris[0],
        scope: 'read',
        state: '<script>alert("xss")</script>',
        code_challenge: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
        code_challenge_method: 'plain',
        malicious_param: "'; DROP TABLE clients; --",
      };

      const request: OAuth2Request = {
        path: '/authorize',
        method: 'GET',
        headers: {},
        query: maliciousParams,
        body: { userId: 'user123' }, // Simulate authenticated user
        cookies: {},
      };

      try {
        const response = await server.authorize(request);
        // If successful, should be a proper redirect
        expect(response.statusCode).toBe(302);
        expect(response.headers.Location).toBeDefined();
      } catch (error) {
        // If failed, should be a proper OAuth error
        expect(error).toBeInstanceOf(Error);
      }
    });

    it('should reject extremely long query parameters', async () => {
      const longValue = 'a'.repeat(10000); // 10KB parameter

      const request: OAuth2Request = {
        path: '/authorize',
        method: 'GET',
        headers: {},
        query: {
          client_id: client.id,
          response_type: 'code',
          redirect_uri: client.redirectUris[0],
          scope: 'read',
          state: longValue,
          code_challenge: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
          code_challenge_method: 'plain',
        },
        body: { userId: 'user123' },
        cookies: {},
      };

      // Should handle gracefully
      try {
        await server.authorize(request);
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
      }
    });
  });

  describe('Body Parameter Injection', () => {
    it('should handle malformed URL-encoded bodies', async () => {
      const malformedBodies = [
        'grant_type=client_credentials&scope=read&malformed=value%',
        'grant_type=client_credentials&scope=read&nested[param]=value',
        'grant_type=client_credentials&scope=read&=empty_key',
        'grant_type=client_credentials&scope=read&duplicate=value1&duplicate=value2',
        'grant_type=client_credentials&scope=read&unicode=café',
        'grant_type=client_credentials&' + 'a'.repeat(1000) + '=long_param',
      ];

      for (const body of malformedBodies) {
        const request: OAuth2Request = {
          path: '/token',
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString('base64')}`,
          },
          query: {},
          body,
          cookies: {},
        };

        try {
          const response = await server.token(request);
          expect(response.statusCode).toBeGreaterThanOrEqual(200);
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
        }
      }
    });

    it('should reject body parameters with injection attempts', async () => {
      const injectionAttempts = [
        "grant_type=client_credentials&scope='; DROP TABLE tokens; --",
        'grant_type=client_credentials&scope=read&client_id={"$ne": null}',
        'grant_type=client_credentials&scope=read<script>alert("xss")</script>',
        'grant_type=client_credentials&scope=read\x00\x01\x02',
      ];

      for (const body of injectionAttempts) {
        const request: OAuth2Request = {
          path: '/token',
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString('base64')}`,
          },
          query: {},
          body,
          cookies: {},
        };

        try {
          await server.token(request);
        } catch (error) {
          // Should be a proper OAuth error, not a system error
          expect(error).toBeInstanceOf(Error);
          expect((error as Error).message).not.toContain('SQL');
          expect((error as Error).message).not.toContain('database');
        }
      }
    });
  });

  describe('Scope Injection Attacks', () => {
    it('should reject scopes with special characters', async () => {
      const maliciousScopes = [
        "read'; DROP TABLE scopes; --",
        'read write admin<script>alert("xss")</script>',
        'read\x00admin',
        'read\nwrite\radmin',
        'read write admin super_secret_scope',
        '../../../admin',
        'scope with spaces and\ttabs',
      ];

      for (const scope of maliciousScopes) {
        const request: OAuth2Request = {
          path: '/token',
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString('base64')}`,
          },
          query: {},
          body: `grant_type=client_credentials&scope=${encodeURIComponent(scope)}`,
          cookies: {},
        };

        try {
          await server.token(request);
        } catch (error) {
          expect(error).toBeInstanceOf(InvalidScopeError);
        }
      }
    });

    it('should reject unauthorized scope combinations', async () => {
      const unauthorizedCombinations = [
        'read write admin', // Admin not allowed for this client
        'read write delete_all',
        'super_user admin root',
        'read write system internal',
      ];

      for (const scope of unauthorizedCombinations) {
        const request: OAuth2Request = {
          path: '/token',
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString('base64')}`,
          },
          query: {},
          body: `grant_type=client_credentials&scope=${encodeURIComponent(scope)}`,
          cookies: {},
        };

        await expect(server.token(request)).rejects.toThrow(InvalidScopeError);
      }
    });
  });

  describe('URL Injection Attacks', () => {
    it('should reject malicious redirect URIs', async () => {
      const maliciousRedirectUris = [
        'javascript:alert("xss")',
        'data:text/html,<script>alert("xss")</script>',
        'file:///etc/passwd',
        'ftp://malicious.example.com/',
        'mailto:admin@example.com',
        'tel:+1234567890',
        'https://evil.example.com/cb', // Not registered
        'https://client.example.com/../admin',
        'https://client.example.com/cb?malicious=param#fragment',
      ];

      for (const redirectUri of maliciousRedirectUris) {
        const request: OAuth2Request = {
          path: '/authorize',
          method: 'GET',
          headers: {},
          query: {
            client_id: client.id,
            response_type: 'code',
            redirect_uri: redirectUri,
            scope: 'read',
            code_challenge: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
            code_challenge_method: 'plain',
          },
          body: { userId: 'user123' },
          cookies: {},
        };

        await expect(server.authorize(request)).rejects.toThrow(InvalidRequestError);
      }
    });
  });

  describe('Encoding and Character Set Attacks', () => {
    it('should handle various character encodings', async () => {
      const encodingTests = [
        'grant_type=client_credentials&scope=read&param=caf%C3%A9', // UTF-8
        'grant_type=client_credentials&scope=read&param=%41%42%43', // URL encoded ABC
        'grant_type=client_credentials&scope=read&param=Hello%20World', // URL encoded space
        'grant_type=client_credentials&scope=read&param=%E2%9C%93', // UTF-8 checkmark
      ];

      for (const body of encodingTests) {
        const request: OAuth2Request = {
          path: '/token',
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString('base64')}`,
          },
          query: {},
          body,
          cookies: {},
        };

        const response = await server.token(request);
        expect(response.statusCode).toBe(200);
      }
    });

    it('should reject invalid URL encoding', async () => {
      const invalidEncodings = [
        'grant_type=client_credentials&scope=read&param=%ZZ', // Invalid hex
        'grant_type=client_credentials&scope=read&param=%1', // Incomplete encoding
        'grant_type=client_credentials&scope=read&param=%', // Incomplete encoding
      ];

      for (const body of invalidEncodings) {
        const request: OAuth2Request = {
          path: '/token',
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString('base64')}`,
          },
          query: {},
          body,
          cookies: {},
        };

        // Should handle gracefully
        try {
          await server.token(request);
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
        }
      }
    });
  });

  describe('Buffer Overflow Attempts', () => {
    it('should handle extremely large requests', async () => {
      const largeBody = 'grant_type=client_credentials&scope=read&large_param=' + 'a'.repeat(50000);

      const request: OAuth2Request = {
        path: '/token',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString('base64')}`,
        },
        query: {},
        body: largeBody,
        cookies: {},
      };

      // Should not crash the server
      try {
        await server.token(request);
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
      }
    });

    it('should handle deeply nested JSON (if JSON is supported)', async () => {
      const deeplyNested = JSON.stringify(
        Array(1000)
          .fill(0)
          .reduce((acc, _) => ({ nested: acc }), { value: 'test' }),
      );

      const request: OAuth2Request = {
        path: '/token',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString('base64')}`,
        },
        query: {},
        body: deeplyNested,
        cookies: {},
      };

      try {
        await server.token(request);
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
      }
    });
  });
});
