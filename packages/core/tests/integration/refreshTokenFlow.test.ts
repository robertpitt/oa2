import { clientCredentialsGrant, createServer, refreshTokenGrant } from '../../src';
import { InMemoryStorageAdapter } from '../mocks/storage';

import { OAuth2Request, Token } from '../../src/types';

describe('Refresh Token Flow Integration', () => {
  let storage: InMemoryStorageAdapter;
  let server: any;
  let client: any;
  let initialToken: Token;

  beforeEach(async () => {
    storage = new InMemoryStorageAdapter();
    client = {
      id: 'test_client',
      secret: 'test_secret',
      redirectUris: [],
      allowedGrants: ['refresh_token', 'client_credentials'],
      scopes: ['read', 'write', 'offline_access'],
    };
    storage.saveClient(client);

    server = createServer({
      storage,
      grants: [refreshTokenGrant(), clientCredentialsGrant()],
      predefinedScopes: ['read', 'write', 'offline_access'],
    });

    // Obtain an initial token with a refresh token
    /**
     * RFC 6749, Section 4.4 Client Credentials Grant
     * Used here to obtain an initial token for testing the refresh token flow.
     */
    const initialTokenRequest: OAuth2Request = {
      path: '/token',
      method: 'POST',
      headers: {
        authorization: 'Basic ' + Buffer.from(`${client.id}:${client.secret}`).toString('base64'),
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      query: {},
      body: 'grant_type=client_credentials&scope=read%20write%20offline_access',
      cookies: {},
    };

    const initialTokenResponse = await server.token(initialTokenRequest);
    initialToken = {
      accessToken: initialTokenResponse.body.access_token,
      accessTokenExpiresAt: new Date(Date.now() + 3600 * 1000),
      refreshToken: initialTokenResponse.body.refresh_token,
      refreshTokenExpiresAt: new Date(Date.now() + 7 * 24 * 3600 * 1000),
      scope: initialTokenResponse.body.scope,
      clientId: client.id,
      userId: client.id,
    };
    // The server.token call already saves the token, so no need to call storage.saveToken again
  });

  it('should successfully refresh an access token using a refresh token', async () => {
    /**
     * RFC 6749, Section 6 Refreshing an Access Token
     * "The client makes a request to the token endpoint by sending the
     * following parameters: grant_type (set to "refresh_token"), refresh_token."
     */
    const refreshTokenRequest: OAuth2Request = {
      path: '/token',
      method: 'POST',
      headers: {
        authorization: 'Basic ' + Buffer.from(`${client.id}:${client.secret}`).toString('base64'),
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      query: {},
      body: `grant_type=refresh_token&refresh_token=${initialToken.refreshToken}`,
      cookies: {},
    };

    const refreshTokenResponse = await server.token(refreshTokenRequest);

    /**
     * RFC 6749, Section 5.1 Successful Response
     * "The authorization server issues an access token and optional refresh token."
     */
    expect(refreshTokenResponse.statusCode).toBe(200);
    expect(refreshTokenResponse.headers['Content-Type']).toBe('application/json');
    expect(refreshTokenResponse.body).toHaveProperty('access_token');
    expect(refreshTokenResponse.body).toHaveProperty('token_type', 'Bearer');
    expect(refreshTokenResponse.body.expires_in).toBeGreaterThan(3590);
    expect(refreshTokenResponse.body.expires_in).toBeLessThanOrEqual(3600);
    expect(refreshTokenResponse.body).toHaveProperty('refresh_token');
    expect(refreshTokenResponse.body).toHaveProperty('scope', initialToken.scope);

    /**
     * RFC 6749, Section 6 Refreshing an Access Token
     * "The authorization server MAY issue a new refresh token, in which case it MUST
     * revoke the old refresh token."
     */
    expect(await storage.getRefreshToken(initialToken.refreshToken!)).toBeNull();

    // Verify new tokens are saved
    const newAccessToken = await storage.getAccessToken(refreshTokenResponse.body.access_token);
    expect(newAccessToken).not.toBeNull();
    expect(newAccessToken?.clientId).toBe(client.id);
    expect(newAccessToken?.userId).toBe(client.id);

    const newRefreshToken = await storage.getRefreshToken(refreshTokenResponse.body.refresh_token);
    expect(newRefreshToken).not.toBeNull();
    expect(newRefreshToken?.clientId).toBe(client.id);
    expect(newRefreshToken?.userId).toBe(client.id);
  });

  it('should successfully refresh an access token with a reduced scope', async () => {
    /**
     * RFC 6749, Section 6 Refreshing an Access Token
     * "The client MAY request a narrower scope than the scope of the issued refresh token."
     */
    const refreshTokenRequest: OAuth2Request = {
      path: '/token',
      method: 'POST',
      headers: {
        authorization: 'Basic ' + Buffer.from(`${client.id}:${client.secret}`).toString('base64'),
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      query: {},
      body: `grant_type=refresh_token&refresh_token=${initialToken.refreshToken}&scope=read`,
      cookies: {},
    };

    const refreshTokenResponse = await server.token(refreshTokenRequest);

    /**
     * RFC 6749, Section 5.1 Successful Response
     */
    expect(refreshTokenResponse.statusCode).toBe(200);
    expect(refreshTokenResponse.headers['Content-Type']).toBe('application/json');
    expect(refreshTokenResponse.body).toHaveProperty('access_token');
    expect(refreshTokenResponse.body).toHaveProperty('token_type', 'Bearer');
    expect(refreshTokenResponse.body.expires_in).toBeGreaterThan(3590);
    expect(refreshTokenResponse.body.expires_in).toBeLessThanOrEqual(3600);
    expect(refreshTokenResponse.body).toHaveProperty('refresh_token');
    expect(refreshTokenResponse.body).toHaveProperty('scope', 'read');

    /**
     * RFC 6749, Section 6 Refreshing an Access Token
     * "The authorization server MAY issue a new refresh token, in which case it MUST
     * revoke the old refresh token."
     */
    expect(await storage.getRefreshToken(initialToken.refreshToken!)).toBeNull();

    // Verify new tokens are saved
    const newAccessToken = await storage.getAccessToken(refreshTokenResponse.body.access_token);
    expect(newAccessToken).not.toBeNull();
    expect(newAccessToken?.clientId).toBe(client.id);
    expect(newAccessToken?.userId).toBe(client.id);

    const newRefreshToken = await storage.getRefreshToken(refreshTokenResponse.body.refresh_token);
    expect(newRefreshToken).not.toBeNull();
    expect(newRefreshToken?.clientId).toBe(client.id);
    expect(newRefreshToken?.userId).toBe(client.id);
  });
});
