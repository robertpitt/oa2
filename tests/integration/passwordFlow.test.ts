import { createServer, passwordGrant } from '../../src';
import { InMemoryStorageAdapter } from '../mocks/storage';
import { OAuth2Request, OAuth2Server } from '../../src/types';

describe('Password Grant Flow Integration', () => {
  let storage: InMemoryStorageAdapter;
  let server: OAuth2Server;
  let client: any;
  let user: any;

  beforeEach(() => {
    storage = new InMemoryStorageAdapter();
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
    (storage as any).users.set(user.id, user);

    server = createServer({
      storage,
      grants: [passwordGrant()],
      predefinedScopes: ['read', 'write'],
    });
  });

  it('should complete the full Password Grant flow', async () => {
    const tokenRequest: OAuth2Request = {
      path: '/token',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: 'Basic ' + Buffer.from(`${client.id}:${client.secret}`).toString('base64'),
      },
      query: {},
      body: `grant_type=password&username=${user.username}&password=${user.password}&scope=read`,
      cookies: {},
    };

    const tokenResponse = await server.token(tokenRequest);

    expect(tokenResponse.statusCode).toBe(200);
    expect(tokenResponse.headers['Content-Type']).toBe('application/json');
    expect(tokenResponse.body).toHaveProperty('access_token');
    expect(tokenResponse.body).toHaveProperty('token_type', 'Bearer');
    expect(tokenResponse.body.expires_in).toBeGreaterThan(3590);
    expect(tokenResponse.body.expires_in).toBeLessThanOrEqual(3600);
    expect(tokenResponse.body).toHaveProperty('scope', 'read');
    expect(tokenResponse.body).not.toHaveProperty('refresh_token');

    const savedAccessToken = await storage.getAccessToken(tokenResponse.body.access_token!);
    expect(savedAccessToken).not.toBeNull();
    expect(savedAccessToken?.clientId).toBe(client.id);
    expect(savedAccessToken?.userId).toBe(user.id);
  });
});
