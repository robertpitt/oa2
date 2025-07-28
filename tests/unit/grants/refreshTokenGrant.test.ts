import { Client, Context, OAuth2Request, refreshTokenGrant, Token } from '../../../src';
import { InMemoryStorageAdapter } from '../../mocks/storage';
import { createTestContext } from '../helpers/testContext';
import { UnauthorizedClientError, InvalidRequestError, InvalidGrantError } from '../../../src/errors';

describe('refreshTokenGrant', () => {
  let storage: InMemoryStorageAdapter;
  let grant: any;
  let client: Client;
  let existingToken: Token;

  beforeEach(() => {
    storage = new InMemoryStorageAdapter();
    grant = refreshTokenGrant();
    client = {
      id: 'test_client',
      secret: 'test_secret',
      redirectUris: [],
      allowedGrants: ['refresh_token'],
      scopes: ['read', 'write', 'offline_access'],
    };
    existingToken = {
      accessToken: 'old_access_token',
      accessTokenExpiresAt: new Date(Date.now() + 3600 * 1000),
      refreshToken: 'valid_refresh_token',
      refreshTokenExpiresAt: new Date(Date.now() + 7 * 24 * 3600 * 1000),
      scope: 'read write',
      clientId: client.id,
      userId: 'test_user',
    };
    storage.saveToken(existingToken);
  });

  it('should throw UnauthorizedClientError if client is not authenticated', async () => {
    const request: OAuth2Request = {
      path: '/token',
      method: 'POST',
      headers: {},
      query: {},
      body: { refresh_token: 'valid_refresh_token' },
      cookies: {},
    };
    const context: Context = {
      request,
      storage,
      client: undefined,
      config: createTestContext({} as any, {} as any).config,
    };

    await expect(grant.handleToken(context)).rejects.toThrow(UnauthorizedClientError);
  });

  it('should throw InvalidRequestError if refresh_token is missing', async () => {
    const request: OAuth2Request = {
      path: '/token',
      method: 'POST',
      headers: {},
      query: {},
      body: {},
      cookies: {},
    };
    const context: Context = createTestContext(request, storage, client, {
      predefinedScopes: ['read', 'write', 'offline_access'],
    });

    await expect(grant.handleToken(context)).rejects.toThrow(InvalidRequestError);
    await expect(grant.handleToken(context)).rejects.toHaveProperty('code', 'invalid_request');
  });

  it('should throw InvalidGrantError if refresh_token is invalid', async () => {
    const request: OAuth2Request = {
      path: '/token',
      method: 'POST',
      headers: {},
      query: {},
      body: { refresh_token: 'invalid_refresh_token' },
      cookies: {},
    };
    const context: Context = createTestContext(request, storage, client, {
      predefinedScopes: ['read', 'write', 'offline_access'],
    });

    await expect(grant.handleToken(context)).rejects.toThrow(InvalidGrantError);
    await expect(grant.handleToken(context)).rejects.toHaveProperty('code', 'invalid_grant');
  });

  it('should throw InvalidGrantError if refresh_token is expired', async () => {
    const expiredToken: Token = {
      accessToken: 'expired_access_token',
      accessTokenExpiresAt: new Date(Date.now() - 3600 * 1000),
      refreshToken: 'expired_refresh_token',
      refreshTokenExpiresAt: new Date(Date.now() - 1000), // 1 second in the past
      scope: 'read',
      clientId: client.id,
      userId: 'test_user',
    };
    await storage.saveToken(expiredToken);

    const request: OAuth2Request = {
      path: '/token',
      method: 'POST',
      headers: {},
      query: {},
      body: { refresh_token: 'expired_refresh_token' },
      cookies: {},
    };
    const context: Context = createTestContext(request, storage, client, {
      predefinedScopes: ['read', 'write', 'offline_access'],
    });

    await expect(grant.handleToken(context)).rejects.toThrow(InvalidGrantError);
    await expect(grant.handleToken(context)).rejects.toHaveProperty('code', 'invalid_grant');
  });

  it('should successfully refresh tokens with no scope specified', async () => {
    const request: OAuth2Request = {
      path: '/token',
      method: 'POST',
      headers: {},
      query: {},
      body: { refresh_token: 'valid_refresh_token' },
      cookies: {},
    };
    const context: Context = createTestContext(request, storage, client, {
      predefinedScopes: ['read', 'write', 'offline_access'],
    });

    const response = await grant.handleToken(context);

    expect(response.statusCode).toBe(200);
    expect(response.headers['Content-Type']).toBe('application/json');
    expect(response.body).toHaveProperty('access_token');
    expect(response.body).toHaveProperty('token_type', 'Bearer');
    expect(response.body).toHaveProperty('expires_in', 3600);
    expect(response.body).toHaveProperty('refresh_token');
    expect(response.body).toHaveProperty('scope', 'read write');

    // Verify old refresh token is revoked
    expect(await storage.getRefreshToken('valid_refresh_token')).toBeNull();

    // Verify new tokens are saved
    const newAccessToken = await storage.getAccessToken(response.body.access_token);
    expect(newAccessToken).not.toBeNull();
    expect(newAccessToken?.clientId).toBe(client.id);
    expect(newAccessToken?.userId).toBe('test_user');
    expect(newAccessToken?.scope).toBe('read write');

    const newRefreshToken = await storage.getRefreshToken(response.body.refresh_token);
    expect(newRefreshToken).not.toBeNull();
    expect(newRefreshToken?.clientId).toBe(client.id);
    expect(newRefreshToken?.userId).toBe('test_user');
    expect(newRefreshToken?.scope).toBe('read write');
  });

  it('should successfully refresh tokens with a new scope (subset of original)', async () => {
    const request: OAuth2Request = {
      path: '/token',
      method: 'POST',
      headers: {},
      query: {},
      body: { refresh_token: 'valid_refresh_token', scope: 'read' },
      cookies: {},
    };
    const context: Context = createTestContext(request, storage, client, {
      predefinedScopes: ['read', 'write', 'offline_access'],
    });

    const response = await grant.handleToken(context);

    expect(response.statusCode).toBe(200);
    expect(response.headers['Content-Type']).toBe('application/json');
    expect(response.body).toHaveProperty('access_token');
    expect(response.body).toHaveProperty('token_type', 'Bearer');
    expect(response.body.expires_in).toBeGreaterThan(3590);
    expect(response.body.expires_in).toBeLessThanOrEqual(3600);
    expect(response.body).toHaveProperty('refresh_token');
    expect(response.body).toHaveProperty('scope', 'read');

    // Verify old refresh token is revoked
    expect(await storage.getRefreshToken('valid_refresh_token')).toBeNull();

    // Verify new tokens are saved
    const newAccessToken = await storage.getAccessToken(response.body.access_token);
    expect(newAccessToken).not.toBeNull();
    expect(newAccessToken?.clientId).toBe(client.id);
    expect(newAccessToken?.userId).toBe('test_user');
    expect(newAccessToken?.scope).toBe('read');

    const newRefreshToken = await storage.getRefreshToken(response.body.refresh_token);
    expect(newRefreshToken).not.toBeNull();
    expect(newRefreshToken?.clientId).toBe(client.id);
    expect(newRefreshToken?.userId).toBe('test_user');
    expect(newRefreshToken?.scope).toBe('read');
  });
});
