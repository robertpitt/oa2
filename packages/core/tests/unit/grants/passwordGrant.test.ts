import {
  passwordGrant,
  Context,
  Client,
  OAuth2Request,
  InvalidRequestError,
  InvalidGrantError,
  UnauthorizedClientError,
} from '../../../src';
import { InMemoryStorageAdapter } from '../../mocks/storage';
import { createTestContext } from '../helpers/testContext';

describe('passwordGrant', () => {
  let storage: InMemoryStorageAdapter;
  let grant: any;
  let client: Client;
  let user: any;

  beforeEach(() => {
    storage = new InMemoryStorageAdapter();
    grant = passwordGrant();
    client = {
      id: 'test_client',
      secret: 'test_secret',
      redirectUris: [],
      allowedGrants: ['password'],
      scopes: ['read', 'write'],
    };
    user = {
      id: 'test_user',
      username: 'testuser',
      password: 'password',
    };
    storage.saveClient(client);
    // The mock storage already has a user, but let's be explicit.
    (storage as any).users.set(user.id, user);
  });

  it('should throw UnauthorizedClientError if client is not authenticated', async () => {
    const request: OAuth2Request = {
      path: '/token',
      method: 'POST',
      headers: {},
      query: {},
      body: { username: 'testuser', password: 'password' },
      cookies: {},
    };
    const context: Context = createTestContext(request, storage, undefined);

    await expect(grant.handleToken(context)).rejects.toThrow(UnauthorizedClientError);
  });

  it('should throw InvalidRequestError if username is missing', async () => {
    const request: OAuth2Request = {
      path: '/token',
      method: 'POST',
      headers: {},
      query: {},
      body: { password: 'password' },
      cookies: {},
    };
    const context: Context = createTestContext(request, storage, client);

    await expect(grant.handleToken(context)).rejects.toThrow(InvalidRequestError);
    await expect(grant.handleToken(context)).rejects.toHaveProperty('code', 'invalid_request');
  });

  it('should throw InvalidRequestError if password is missing', async () => {
    const request: OAuth2Request = {
      path: '/token',
      method: 'POST',
      headers: {},
      query: {},
      body: { username: 'testuser' },
      cookies: {},
    };
    const context: Context = createTestContext(request, storage, client);

    await expect(grant.handleToken(context)).rejects.toThrow(InvalidRequestError);
    await expect(grant.handleToken(context)).rejects.toHaveProperty('code', 'invalid_request');
  });

  it('should throw InvalidGrantError if credentials are invalid', async () => {
    const request: OAuth2Request = {
      path: '/token',
      method: 'POST',
      headers: {},
      query: {},
      body: { username: 'testuser', password: 'wrong_password' },
      cookies: {},
    };
    const context: Context = createTestContext(request, storage, client);

    await expect(grant.handleToken(context)).rejects.toThrow(InvalidGrantError);
    await expect(grant.handleToken(context)).rejects.toHaveProperty('code', 'invalid_grant');
  });

  it('should successfully exchange username/password for tokens', async () => {
    const request: OAuth2Request = {
      path: '/token',
      method: 'POST',
      headers: {},
      query: {},
      body: { grant_type: 'password', username: 'testuser', password: 'password', scope: 'read' },
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
    expect(response.body).toHaveProperty('scope', 'read');
    expect(response.body).not.toHaveProperty('refresh_token');

    const savedAccessToken = await storage.getAccessToken(response.body.access_token);
    expect(savedAccessToken).not.toBeNull();
    expect(savedAccessToken?.clientId).toBe(client.id);
    expect(savedAccessToken?.userId).toBe('test_user');
    expect(savedAccessToken?.scope).toBe('read');
  });
});
