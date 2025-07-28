import { Client, clientCredentialsGrant, Context, InvalidRequestError, OAuth2Request } from '../../../src';
import { InMemoryStorageAdapter } from '../../mocks/storage';
import { createTestContext } from '../helpers/testContext';
import { UnauthorizedClientError } from '../../../src/errors';

describe('clientCredentialsGrant', () => {
  let storage: InMemoryStorageAdapter;
  let grant: any;
  let client: Client;

  beforeEach(() => {
    storage = new InMemoryStorageAdapter();
    grant = clientCredentialsGrant();
    client = {
      id: 'test_client',
      secret: 'test_secret',
      redirectUris: [],
      allowedGrants: ['client_credentials'],
      scopes: ['read', 'write'],
    };
  });

  it('should throw UnauthorizedClientError if client is not authenticated', async () => {
    const request: OAuth2Request = {
      path: '/token',
      method: 'POST',
      headers: {},
      query: {},
      body: {},
      cookies: {},
    };
    const context: Context = createTestContext(request, storage, undefined);

    await expect(grant.handleToken(context)).rejects.toThrow(UnauthorizedClientError);
  });

  it('should successfully exchange client credentials for tokens with no scope', async () => {
    const request: OAuth2Request = {
      path: '/token',
      method: 'POST',
      headers: {},
      query: {},
      body: {},
      cookies: {},
    };
    const context: Context = createTestContext(request, storage, client);

    const response = await grant.handleToken(context);

    expect(response.statusCode).toBe(200);
    expect(response.headers['Content-Type']).toBe('application/json');
    expect(response.body).toHaveProperty('access_token');
    expect(response.body).toHaveProperty('token_type', 'Bearer');
    expect(response.body.expires_in).toBeGreaterThan(3590);
    expect(response.body.expires_in).toBeLessThanOrEqual(3600);
    expect(response.body).toHaveProperty('scope', '');

    const savedAccessToken = await storage.getAccessToken(response.body.access_token);
    expect(savedAccessToken).not.toBeNull();
    expect(savedAccessToken?.clientId).toBe(client.id);
    expect(savedAccessToken?.userId).toBe(client.id);
    expect(savedAccessToken?.scope).toBe('');
  });

  it('should successfully exchange client credentials for tokens with scope', async () => {
    const request: OAuth2Request = {
      path: '/token',
      method: 'POST',
      headers: {},
      query: {},
      body: { scope: 'read write' },
      cookies: {},
    };
    const context: Context = createTestContext(request, storage, client);

    const response = await grant.handleToken(context);

    expect(response.statusCode).toBe(200);
    expect(response.headers['Content-Type']).toBe('application/json');
    expect(response.body).toHaveProperty('access_token');
    expect(response.body).toHaveProperty('token_type', 'Bearer');
    expect(response.body.expires_in).toBeGreaterThan(3590);
    expect(response.body.expires_in).toBeLessThanOrEqual(3600);
    expect(response.body).toHaveProperty('scope', 'read write');

    const savedAccessToken = await storage.getAccessToken(response.body.access_token);
    expect(savedAccessToken).not.toBeNull();
    expect(savedAccessToken?.clientId).toBe(client.id);
    expect(savedAccessToken?.userId).toBe(client.id);
    expect(savedAccessToken?.scope).toBe('read write');
  });
});
