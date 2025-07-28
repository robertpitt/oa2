import { createServer, authorizationCodeGrant, clientCredentialsGrant } from '../../src';
import { InMemoryStorageAdapter } from '../mocks/storage';

import { OAuth2Request, OAuth2Server } from '../../src/types';
import * as crypto from 'crypto';

describe('Authorization Code Flow Integration', () => {
  let storage: InMemoryStorageAdapter;
  let server: OAuth2Server;
  let client: any;

  beforeEach(() => {
    storage = new InMemoryStorageAdapter();
    client = {
      id: 'test_client',
      secret: 'test_secret',
      redirectUris: ['https://client.example.com/cb'],
      allowedGrants: ['authorization_code', 'client_credentials'],
      scopes: ['read', 'write'],
    };
    storage.saveClient(client);

    server = createServer({
      storage,
      grants: [authorizationCodeGrant(), clientCredentialsGrant()],
      predefinedScopes: ['read', 'write'],
    });
  });

  it('should complete the full Authorization Code flow with PKCE (S256)', async () => {
    /**
     * RFC 7636, Section 4.1 Client Creates a Code Verifier
     * RFC 7636, Section 4.2 Client Creates the Code Challenge
     */
    const codeVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    const codeChallenge = crypto
      .createHash('sha256')
      .update(codeVerifier)
      .digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    // Step 1: Authorization Request
    /**
     * RFC 6749, Section 4.1.1 Authorization Request
     * RFC 7636, Section 4.3 Client Sends the Code Challenge with the Authorization Request
     */
    const authRequest: OAuth2Request = {
      path: '/authorize',
      method: 'GET',
      headers: {},
      query: {
        response_type: 'code',
        client_id: client.id,
        redirect_uri: client.redirectUris[0],
        scope: 'read write',
        state: 'xyz',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      },
      body: { userId: 'test_user' }, // Simulate authenticated user
      cookies: {},
    };

    const authResponse = await server.authorize(authRequest);

    /**
     * RFC 6749, Section 4.1.2 Authorization Response
     * The authorization server redirects the user-agent back to the client with the authorization code.
     */
    expect(authResponse.statusCode).toBe(302);
    expect(authResponse.headers.Location).toBeDefined();
    const authCodeUrl = new URL(authResponse.headers.Location as string);
    const authorizationCode = authCodeUrl.searchParams.get('code');
    const state = authCodeUrl.searchParams.get('state');

    expect(authorizationCode).not.toBeNull();
    expect(state).toBe('xyz');

    // Step 2: Token Request
    /**
     * RFC 6749, Section 4.1.3 Access Token Request
     * RFC 7636, Section 4.5 Client Sends the Authorization Code and the Code Verifier to the Token Endpoint
     * RFC 6749, Section 2.3.1 Client Password (for Basic Authentication)
     */
    const tokenRequest: OAuth2Request = {
      path: '/token',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: 'Basic ' + Buffer.from(`${client.id}:${client.secret}`).toString('base64'),
      },
      query: {},
      body: `grant_type=authorization_code&code=${authorizationCode}&redirect_uri=${client.redirectUris[0]}&client_id=${client.id}&client_secret=${client.secret}&code_verifier=${codeVerifier}`,
      cookies: {},
    };

    const tokenResponse = await server.token(tokenRequest);

    /**
     * RFC 6749, Section 4.1.4 Access Token Response
     * RFC 6749, Section 5.1 Successful Response
     */
    expect(tokenResponse.statusCode).toBe(200);
    expect(tokenResponse.headers['Content-Type']).toBe('application/json');
    expect(tokenResponse.body).toHaveProperty('access_token');
    expect(tokenResponse.body).toHaveProperty('token_type', 'Bearer');
    expect(tokenResponse.body.expires_in).toBeGreaterThan(3590);
    expect(tokenResponse.body.expires_in).toBeLessThanOrEqual(3600);
    expect(tokenResponse.body).toHaveProperty('refresh_token');
    expect(tokenResponse.body).toHaveProperty('scope', 'read write');

    /**
     * RFC 6749, Section 4.1.2 Authorization Response
     * "The client MUST NOT use the authorization code more than once."
     */
    expect(await storage.getAuthorizationCode(authorizationCode as string)).toBeNull();

    // Verify tokens are saved
    const savedAccessToken = await storage.getAccessToken(tokenResponse.body.access_token!);
    expect(savedAccessToken).not.toBeNull();
    expect(savedAccessToken?.clientId).toBe(client.id);
    expect(savedAccessToken?.userId).toBe('test_user');

    const savedRefreshToken = await storage.getRefreshToken(tokenResponse.body.refresh_token);
    expect(savedRefreshToken).not.toBeNull();
    expect(savedRefreshToken?.clientId).toBe(client.id);
    expect(savedRefreshToken?.userId).toBe('test_user');
  });
});
