import {
  Client,
  Context,
  createServer,
  Grant,
  InvalidRequestError,
  OAuth2Request,
  UnauthorizedClientError,
  UnsupportedGrantTypeError,
  UnsupportedResponseTypeError,
} from '../../../src';
import { InMemoryStorageAdapter } from '../../mocks/storage';

describe('createServer', () => {
  let storage: InMemoryStorageAdapter;
  let mockAuthCodeGrant: Grant;
  let mockClientCredentialsGrant: Grant;
  let mockRefreshTokenGrant: Grant;
  let server: any;
  let client: Client;

  beforeEach(() => {
    storage = new InMemoryStorageAdapter();
    client = {
      id: 'test_client',
      secret: 'test_secret',
      redirectUris: ['http://localhost/cb'],
      allowedGrants: ['authorization_code', 'client_credentials', 'refresh_token'],
      scopes: ['a', 'b'],
    };
    storage.saveClient(client);

    mockAuthCodeGrant = {
      type: 'authorization_code',
      handleAuthorization: jest.fn(async (context: Context) => {
        return { statusCode: 200, headers: {}, body: { message: 'Auth code handled' }, cookies: {} };
      }),
    };

    mockClientCredentialsGrant = {
      type: 'client_credentials',
      handleToken: jest.fn(async (context: Context) => {
        return { statusCode: 200, headers: {}, body: { message: 'Client credentials handled' }, cookies: {} };
      }),
    };

    mockRefreshTokenGrant = {
      type: 'refresh_token',
      handleToken: jest.fn(async (context: Context) => {
        return { statusCode: 200, headers: {}, body: { message: 'Refresh token handled' }, cookies: {} };
      }),
    };

    server = createServer({
      storage,
      grants: [mockAuthCodeGrant, mockClientCredentialsGrant, mockRefreshTokenGrant],
      predefinedScopes: ['a', 'b'],
    });
  });

  // Authorize Endpoint Tests
  describe('authorize', () => {
    it('should throw InvalidRequestError if response_type is missing', async () => {
      const request: OAuth2Request = {
        path: '/authorize',
        method: 'GET',
        headers: {},
        query: {},
        body: {},
        cookies: {},
      };
      await expect(server.authorize(request)).rejects.toThrow(InvalidRequestError);
      await expect(server.authorize(request)).rejects.toHaveProperty('code', 'invalid_request');
    });

    it('should throw UnsupportedResponseTypeError if response_type is unsupported', async () => {
      const request: OAuth2Request = {
        path: '/authorize',
        method: 'GET',
        headers: {},
        query: { response_type: 'unsupported_type', client_id: client.id },
        body: { userId: 'test_user' },
        cookies: {},
      };
      await expect(server.authorize(request)).rejects.toThrow(UnsupportedResponseTypeError);
      await expect(server.authorize(request)).rejects.toHaveProperty('code', 'unsupported_response_type');
    });
  });

  // Token Endpoint Tests
  describe('token', () => {
    it('should throw InvalidRequestError if grant_type is missing', async () => {
      const request: OAuth2Request = {
        path: '/token',
        method: 'POST',
        headers: { authorization: 'Basic ' + Buffer.from('test_client:test_secret').toString('base64') },
        query: {},
        body: {},
        cookies: {},
      };
      await expect(server.token(request)).rejects.toThrow(InvalidRequestError);
      await expect(server.token(request)).rejects.toHaveProperty('code', 'invalid_request');
    });

    it('should throw InvalidGrantError if grant_type is unsupported', async () => {
      const request: OAuth2Request = {
        path: '/token',
        method: 'POST',
        headers: { authorization: 'Basic ' + Buffer.from('test_client:test_secret').toString('base64') },
        query: {},
        body: { grant_type: 'unsupported_grant' },
        cookies: {},
      };
      await expect(server.token(request)).rejects.toThrow(UnsupportedGrantTypeError);
      await expect(server.token(request)).rejects.toHaveProperty('code', 'unsupported_grant_type');
    });

    it('should delegate to the correct client_credentials grant handler', async () => {
      const request: OAuth2Request = {
        path: '/token',
        method: 'POST',
        headers: { authorization: 'Basic ' + Buffer.from('test_client:test_secret').toString('base64') },
        query: {},
        body: { grant_type: 'client_credentials' },
        cookies: {},
      };
      const response = await server.token(request);
      expect(mockClientCredentialsGrant.handleToken).toHaveBeenCalledTimes(1);
      expect(response.body).toEqual({ message: 'Client credentials handled' });
    });

    it('should delegate to the correct refresh_token grant handler', async () => {
      const request: OAuth2Request = {
        path: '/token',
        method: 'POST',
        headers: { authorization: 'Basic ' + Buffer.from('test_client:test_secret').toString('base64') },
        query: {},
        body: { grant_type: 'refresh_token', refresh_token: 'some_token' },
        cookies: {},
      };
      const response = await server.token(request);
      expect(mockRefreshTokenGrant.handleToken).toHaveBeenCalledTimes(1);
      expect(response.body).toEqual({ message: 'Refresh token handled' });
    });

    it('should throw UnauthorizedClientError if client authentication fails due to invalid client_secret', async () => {
      const request: OAuth2Request = {
        path: '/token',
        method: 'POST',
        headers: { authorization: 'Basic ' + Buffer.from('test_client:wrong_secret').toString('base64') },
        query: {},
        body: { grant_type: 'client_credentials' },
        cookies: {},
      };
      await expect(server.token(request)).rejects.toThrow(UnauthorizedClientError);
      await expect(server.token(request)).rejects.toHaveProperty('code', 'unauthorized_client');
    });
  });

  // Revoke Endpoint Tests
  describe('revoke', () => {
    it('should delegate to the revokeEndpoint', async () => {
      const request: OAuth2Request = {
        path: '/revoke',
        method: 'POST',
        headers: {},
        query: {},
        body: { token: 'some_token' },
        cookies: {},
      };
      const response = await server.revoke(request);
      // We can't directly mock revokeEndpoint as it's imported, but we can check the outcome
      expect(response.statusCode).toBe(200);
      expect(await storage.getAccessToken('some_token')).toBeNull(); // Assuming revokeEndpoint deletes the token
    });
  });

  // Introspect Endpoint Tests
  describe('introspect', () => {
    it('should delegate to the introspectEndpoint', async () => {
      const request: OAuth2Request = {
        path: '/introspect',
        method: 'POST',
        headers: {},
        query: {},
        body: { token: 'some_token' },
        cookies: {},
      };
      const response = await server.introspect(request);
      // We can't directly mock introspectEndpoint as it's imported, but we can check the outcome
      expect(response.statusCode).toBe(200);
      expect(response.body).toEqual({ active: false }); // Assuming an unknown token is passed
    });
  });
});
