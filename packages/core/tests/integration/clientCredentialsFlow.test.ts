import { clientCredentialsGrant, createServer, OAuth2Request } from '../../src';
import { InMemoryStorageAdapter } from '../mocks/storage';

describe('Client Credentials Flow Integration', () => {
  let storage: InMemoryStorageAdapter;
  let server: any;
  let client: any;

  beforeEach(() => {
    storage = new InMemoryStorageAdapter();
    client = {
      id: 'test_client',
      secret: 'test_secret',
      redirectUris: [],
      allowedGrants: ['client_credentials'],
      scopes: ['read', 'write'],
    };
    storage.saveClient(client);

    server = createServer({
      storage,
      grants: [clientCredentialsGrant()],
      predefinedScopes: ['read', 'write'],
    });
  });

  it('should complete the full Client Credentials flow', async () => {
    /**
     * RFC 6749, Section 4.4 Client Credentials Grant
     * RFC 6749, Section 4.4.2 Access Token Request
     * RFC 6749, Section 2.3.1 Client Password (for Basic Authentication)
     */
    const tokenRequest: OAuth2Request = {
      path: '/token',
      method: 'POST',
      headers: {
        authorization: 'Basic ' + Buffer.from(`${client.id}:${client.secret}`).toString('base64'),
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      query: {},
      body: 'grant_type=client_credentials&scope=read%20write',
      cookies: {},
    };

    const tokenResponse = await server.token(tokenRequest);

    /**
     * RFC 6749, Section 5.1 Successful Response
     */
    expect(tokenResponse.statusCode).toBe(200);
    expect(tokenResponse.headers['Content-Type']).toBe('application/json');
    expect(tokenResponse.body).toHaveProperty('access_token');
    expect(tokenResponse.body).toHaveProperty('token_type', 'Bearer');
    expect(tokenResponse.body.expires_in).toBeLessThanOrEqual(3600);
    expect(tokenResponse.body.expires_in).toBeGreaterThan(3590);
    expect(tokenResponse.body).toHaveProperty('scope', 'read write');

    // Verify token is saved
    const savedAccessToken = await storage.getAccessToken(tokenResponse.body.access_token);
    expect(savedAccessToken).not.toBeNull();
    expect(savedAccessToken?.clientId).toBe(client.id);
    expect(savedAccessToken?.userId).toBe(client.id);
    expect(savedAccessToken?.scope).toBe('read write');
  });
});
