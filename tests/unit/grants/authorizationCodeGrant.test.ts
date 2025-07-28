import {
  authorizationCodeGrant,
  OAuth2Request,
  Context,
  Client,
  InvalidRequestError,
  InvalidGrantError,
} from '../../../src';
import { InMemoryStorageAdapter } from '../../mocks/storage';
import { createTestContext } from '../helpers/testContext';
import * as crypto from 'crypto';

describe('authorizationCodeGrant', () => {
  let storage: InMemoryStorageAdapter;
  let grant: any;
  let client: Client;

  beforeEach(() => {
    storage = new InMemoryStorageAdapter();
    grant = authorizationCodeGrant();
    client = {
      id: 'test_client',
      secret: 'test_secret',
      redirectUris: ['https://client.example.com/cb'],
      allowedGrants: ['authorization_code'],
      scopes: ['a', 'b', 'offline_access'],
    };
  });

  it('should throw InvalidRequestError if code is missing when client is not authenticated', async () => {
    const request: OAuth2Request = {
      path: '/token',
      method: 'POST',
      headers: {},
      query: {},
      body: {},
      cookies: {},
    };
    const context: Context = createTestContext(request, storage, client);

    await expect(grant.handleToken(context)).rejects.toThrow(InvalidRequestError);
  });

  it('should throw InvalidRequestError if code is missing', async () => {
    const request: OAuth2Request = {
      path: '/token',
      method: 'POST',
      headers: {},
      query: {},
      body: {
        redirect_uri: 'https://client.example.com/cb',
        code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
      },
      cookies: {},
    };
    const context: Context = createTestContext(request, storage, client);

    await expect(grant.handleToken(context)).rejects.toThrow(InvalidRequestError);
    await expect(grant.handleToken(context)).rejects.toHaveProperty('code', 'invalid_request');
  });

  it('should throw InvalidRequestError if redirect_uri is missing', async () => {
    const request: OAuth2Request = {
      path: '/token',
      method: 'POST',
      headers: {},
      query: {},
      body: {
        redirect_uri: 'https://client.example.com/cb',
        code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
      },
      cookies: {},
    };
    const context: Context = createTestContext(request, storage, client);

    await expect(grant.handleToken(context)).rejects.toThrow(InvalidRequestError);
    await expect(grant.handleToken(context)).rejects.toHaveProperty('code', 'invalid_request');
  });

  it('should throw InvalidRequestError if code_verifier is missing', async () => {
    const request: OAuth2Request = {
      path: '/token',
      method: 'POST',
      headers: {},
      query: { code: '123', redirect_uri: 'https://client.example.com/cb' },
      body: {},
      cookies: {},
    };
    const context: Context = createTestContext(request, storage, client);

    await expect(grant.handleToken(context)).rejects.toThrow(InvalidRequestError);
    await expect(grant.handleToken(context)).rejects.toHaveProperty('code', 'invalid_request');
  });

  it('should throw InvalidGrantError if authorization code is invalid', async () => {
    const request: OAuth2Request = {
      path: '/token',
      method: 'POST',
      headers: {},
      query: {},
      body: {
        code: 'invalid_code',
        redirect_uri: 'https://client.example.com/cb',
        code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
      },
      cookies: {},
    };
    const context: Context = createTestContext(request, storage, client);

    await expect(grant.handleToken(context)).rejects.toThrow(InvalidGrantError);
    await expect(grant.handleToken(context)).rejects.toHaveProperty('code', 'invalid_grant');
  });

  it('should throw InvalidGrantError if authorization code is expired', async () => {
    const expiredCode = 'expired_code';
    const expiredAuthCode = {
      code: expiredCode,
      expiresAt: new Date(Date.now() - 1000), // 1 second in the past
      redirectUri: 'https://client.example.com/cb',
      scope: 'read',
      clientId: client.id,
      userId: 'test_user',
      codeChallenge: 'challenge',
      codeChallengeMethod: 'plain' as 'plain' | 'S256',
    };
    await storage.saveAuthorizationCode(expiredAuthCode);

    const request: OAuth2Request = {
      path: '/token',
      method: 'POST',
      headers: {},
      query: {},
      body: {
        code: expiredCode,
        redirect_uri: 'https://client.example.com/cb',
        code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
      },
      cookies: {},
    };
    const context: Context = createTestContext(request, storage, client);

    await expect(grant.handleToken(context)).rejects.toThrow(InvalidGrantError);
    await expect(grant.handleToken(context)).rejects.toHaveProperty('code', 'invalid_grant');
  });

  it('should throw InvalidGrantError if code_verifier is invalid (plain)', async () => {
    const authCode = {
      code: 'valid_code',
      expiresAt: new Date(Date.now() + 60000), // 1 minute in the future
      redirectUri: 'https://client.example.com/cb',
      scope: 'read',
      clientId: client.id,
      userId: 'test_user',
      codeChallenge: 'correct_challenge',
      codeChallengeMethod: 'plain' as 'plain' | 'S256',
    };
    await storage.saveAuthorizationCode(authCode);

    const request: OAuth2Request = {
      path: '/token',
      method: 'POST',
      headers: {},
      query: {},
      body: {
        code: 'valid_code',
        redirect_uri: 'https://client.example.com/cb',
        code_verifier: 'wrongCodeVerifierThatIsLongEnoughButStillWrong',
      },
      cookies: {},
    };
    const context: Context = createTestContext(request, storage, client);

    await expect(grant.handleToken(context)).rejects.toThrow(InvalidGrantError);
    await expect(grant.handleToken(context)).rejects.toHaveProperty('code', 'invalid_grant');
  });

  it('should throw InvalidGrantError if code_verifier is invalid (S256)', async () => {
    const codeVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    const codeChallenge = crypto
      .createHash('sha256')
      .update('another_random_string')
      .digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    const authCode = {
      code: 'valid_code_s256',
      expiresAt: new Date(Date.now() + 60000),
      redirectUri: 'https://client.example.com/cb',
      scope: 'read',
      clientId: client.id,
      userId: 'test_user',
      codeChallenge: codeChallenge,
      codeChallengeMethod: 'S256' as 'plain' | 'S256',
    };
    await storage.saveAuthorizationCode(authCode);

    const request: OAuth2Request = {
      path: '/token',
      method: 'POST',
      headers: {},
      query: {},
      body: { code: 'valid_code_s256', redirect_uri: 'https://client.example.com/cb', code_verifier: codeVerifier },
      cookies: {},
    };
    const context: Context = createTestContext(request, storage, client);

    await expect(grant.handleToken(context)).rejects.toThrow(InvalidGrantError);
    await expect(grant.handleToken(context)).rejects.toHaveProperty('code', 'invalid_grant');
  });

  it('should throw InvalidRequestError if code_challenge_method is unsupported', async () => {
    const authCode = {
      code: 'valid_code_unsupported_method',
      expiresAt: new Date(Date.now() + 60000),
      redirectUri: 'https://client.example.com/cb',
      scope: 'read',
      clientId: client.id,
      userId: 'test_user',
      codeChallenge: 'challenge',
      codeChallengeMethod: 'unsupported' as any, // Simulate an unsupported method
    };
    await storage.saveAuthorizationCode(authCode);

    const request: OAuth2Request = {
      path: '/token',
      method: 'POST',
      headers: {},
      query: {},
      body: {
        code: 'valid_code_unsupported_method',
        redirect_uri: 'https://client.example.com/cb',
        code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
      },
      cookies: {},
    };
    const context: Context = createTestContext(request, storage, client);

    await expect(grant.handleToken(context)).rejects.toThrow(InvalidRequestError);
    await expect(grant.handleToken(context)).rejects.toHaveProperty('code', 'invalid_request');
  });

  it('should successfully exchange authorization code for tokens (plain)', async () => {
    const codeVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    const codeChallenge = codeVerifier; // For plain method

    const authCode = {
      code: 'valid_code_plain',
      expiresAt: new Date(Date.now() + 60000),
      redirectUri: 'https://client.example.com/cb',
      scope: 'read write',
      clientId: client.id,
      userId: 'test_user',
      codeChallenge: codeChallenge,
      codeChallengeMethod: 'plain' as 'plain' | 'S256',
    };
    await storage.saveAuthorizationCode(authCode);

    const request: OAuth2Request = {
      path: '/token',
      method: 'POST',
      headers: {},
      query: {},
      body: { code: 'valid_code_plain', redirect_uri: 'https://client.example.com/cb', code_verifier: codeVerifier },
      cookies: {},
    };
    const context: Context = createTestContext(request, storage, client);

    const response = await grant.handleToken(context);

    expect(response.statusCode).toBe(200);
    expect(response.headers['Content-Type']).toBe('application/json');
    expect(response.body).toHaveProperty('access_token');
    expect(response.body).toHaveProperty('token_type', 'Bearer');
    expect(response.body.expires_in).toBeLessThanOrEqual(3600);
    expect(response.body.expires_in).toBeGreaterThan(3590);
    expect(response.body).toHaveProperty('refresh_token');
    expect(response.body).toHaveProperty('scope', 'read write');

    // Verify authorization code is deleted
    expect(await storage.getAuthorizationCode('valid_code_plain')).toBeNull();

    // Verify tokens are saved
    const savedAccessToken = await storage.getAccessToken(response.body.access_token);
    expect(savedAccessToken).not.toBeNull();
    expect(savedAccessToken?.clientId).toBe(client.id);
    expect(savedAccessToken?.userId).toBe('test_user');

    const savedRefreshToken = await storage.getRefreshToken(response.body.refresh_token);
    expect(savedRefreshToken).not.toBeNull();
    expect(savedRefreshToken?.clientId).toBe(client.id);
    expect(savedRefreshToken?.userId).toBe('test_user');
  });

  it('should successfully exchange authorization code for tokens (S256)', async () => {
    const codeVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    const codeChallenge = crypto
      .createHash('sha256')
      .update(codeVerifier)
      .digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    const authCode = {
      code: 'valid_code_s256_success',
      expiresAt: new Date(Date.now() + 60000),
      redirectUri: 'https://client.example.com/cb',
      scope: 'profile',
      clientId: client.id,
      userId: 'test_user',
      codeChallenge: codeChallenge,
      codeChallengeMethod: 'S256' as 'plain' | 'S256',
    };
    await storage.saveAuthorizationCode(authCode);

    const request: OAuth2Request = {
      path: '/token',
      method: 'POST',
      headers: {},
      query: {},
      body: {
        code: 'valid_code_s256_success',
        redirect_uri: 'https://client.example.com/cb',
        code_verifier: codeVerifier,
      },
      cookies: {},
    };
    const context: Context = createTestContext(request, storage, client);

    const response = await grant.handleToken(context);

    expect(response.statusCode).toBe(200);
    expect(response.headers['Content-Type']).toBe('application/json');
    expect(response.body).toHaveProperty('access_token');
    expect(response.body).toHaveProperty('token_type', 'Bearer');
    expect(response.body.expires_in).toBeLessThanOrEqual(3600);
    expect(response.body.expires_in).toBeGreaterThan(3590);
    expect(response.body).toHaveProperty('refresh_token');
    expect(response.body).toHaveProperty('scope', 'profile');

    // Verify authorization code is deleted
    expect(await storage.getAuthorizationCode('valid_code_s256_success')).toBeNull();

    // Verify tokens are saved
    const savedAccessToken = await storage.getAccessToken(response.body.access_token);
    expect(savedAccessToken).not.toBeNull();
    expect(savedAccessToken?.clientId).toBe(client.id);
    expect(savedAccessToken?.userId).toBe('test_user');

    const savedRefreshToken = await storage.getRefreshToken(response.body.refresh_token);
    expect(savedRefreshToken).not.toBeNull();
    expect(savedRefreshToken?.clientId).toBe(client.id);
    expect(savedRefreshToken?.userId).toBe('test_user');
  });
});
