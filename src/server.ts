import {
  OAuth2Request,
  OAuth2Response,
  OAuth2Server,
  Context,
  Grant,
  Client,
  StorageAdapter,
  ServerConfig,
  TokenStrategy,
} from './types';
import {
  InvalidRequestError,
  UnsupportedResponseTypeError,
  UnauthorizedClientError,
  UnsupportedGrantTypeError,
} from './errors';
import { extractBasicAuthCredentials, parseRequestBody, verifyClientSecret } from './utils';
import { createOpaqueTokenStrategy } from './tokens/opaque';

/**
 * Authenticates a client using the provided credentials.
 * Supports both Basic authentication and form-based credentials.
 */
async function authenticateClient(request: OAuth2Request, storage: StorageAdapter): Promise<Client> {
  const body = parseRequestBody(request);
  const { client_id, client_secret } = body;

  let authenticatedClientId: string | undefined;
  let authenticatedClientSecret: string | undefined;

  // Try Basic authentication first
  const basicAuth = extractBasicAuthCredentials(request.headers.authorization || request.headers.Authorization);
  if (basicAuth) {
    authenticatedClientId = basicAuth.clientId;
    authenticatedClientSecret = basicAuth.clientSecret;
  } else if (client_id && client_secret) {
    // Fall back to form-based authentication
    authenticatedClientId = client_id;
    authenticatedClientSecret = client_secret;
  } else if (client_id) {
    // Public client (no secret required)
    authenticatedClientId = client_id;
  } else {
    throw new InvalidRequestError('Client authentication required');
  }

  if (!authenticatedClientId || authenticatedClientId.trim() === '') {
    throw new UnauthorizedClientError('Client not found');
  }

  const client = await storage.getClient(authenticatedClientId);
  if (!client) {
    throw new UnauthorizedClientError('Client not found');
  }

  // Verify client secret if provided
  if (authenticatedClientSecret && client.secret) {
    if (!verifyClientSecret(authenticatedClientSecret, client.secret)) {
      throw new UnauthorizedClientError('Invalid client credentials');
    }
  }

  return client;
}

/**
 * Finds a grant that supports the specified response type.
 * Used for authorization endpoint requests.
 */
function findGrantByResponseType(grants: Grant[], responseType: string): Grant {
  const responseTypeGrants = grants.filter(
    (grant) => grant.handleAuthorization && grant.responseTypes?.includes(responseType),
  );

  const grant = responseTypeGrants[0];
  if (!grant) {
    throw new UnsupportedResponseTypeError(`Unsupported response_type: ${responseType}`);
  }

  return grant;
}

/**
 * Finds a grant that supports the specified grant type.
 * Used for token endpoint requests.
 */
function findGrantByType(grants: Grant[], grantType: string): Grant {
  const grant = grants.find((g) => g.type === grantType);
  if (!grant) {
    throw new UnsupportedGrantTypeError(`Unsupported grant_type: ${grantType}`);
  }

  return grant;
}

/**
 * Creates a complete server configuration with defaults.
 * Ensures all required fields are present and valid.
 */
function createCompleteConfig(config: ServerConfig): ServerConfig & { tokenStrategy: TokenStrategy } {
  return {
    ...config,
    tokenStrategy:
      config.tokenStrategy ||
      createOpaqueTokenStrategy({
        accessTokenExpiresIn: config.accessTokenLifetime || 3600,
        refreshTokenExpiresIn: config.refreshTokenLifetime || 604800,
      }),
  };
}

/**
 * Creates a context object for grant handlers.
 * Includes all necessary information for processing OAuth 2.0 requests.
 */
function createContext(
  request: OAuth2Request,
  storage: StorageAdapter,
  client: Client | undefined,
  config: ServerConfig & { tokenStrategy: TokenStrategy },
): Context {
  return {
    request,
    storage,
    client,
    config,
  };
}

/**
 * Processes an authorization request and delegates to the appropriate grant handler.
 * Validates the request parameters and client before proceeding.
 */
async function handleAuthorizeRequest(
  request: OAuth2Request,
  storage: StorageAdapter,
  config: ServerConfig & { tokenStrategy: TokenStrategy },
): Promise<OAuth2Response> {
  const { client_id, response_type } = request.query;

  if (!client_id) {
    throw new InvalidRequestError('Missing client_id parameter');
  }

  if (!response_type) {
    throw new InvalidRequestError('Missing response_type parameter');
  }

  // Find the appropriate grant for this response type
  const grant = findGrantByResponseType(config.grants, response_type);

  // Get the client
  const client = await storage.getClient(client_id);
  if (!client) {
    throw new UnauthorizedClientError('Client not found');
  }

  // Create context and delegate to grant handler
  const context = createContext(request, storage, client, config);
  if (!grant.handleAuthorization) {
    throw new UnsupportedResponseTypeError(`Grant does not support authorization requests: ${response_type}`);
  }

  return grant.handleAuthorization(context);
}

/**
 * Token Endpoint
 * ==============
 * Handles OAuth 2.0 token requests.
 */

/**
 * Processes a token request and delegates to the appropriate grant handler.
 * Performs client authentication and grant type validation.
 */
async function handleTokenRequest(
  request: OAuth2Request,
  storage: StorageAdapter,
  config: ServerConfig & { tokenStrategy: TokenStrategy },
): Promise<OAuth2Response> {
  const body = parseRequestBody(request);
  const { grant_type } = body;

  if (!grant_type) {
    throw new InvalidRequestError('Missing grant_type parameter');
  }

  // Authenticate the client
  const client = await authenticateClient(request, storage);

  // Find the appropriate grant for this grant type
  const grant = findGrantByType(config.grants, grant_type);

  // Create context and delegate to grant handler
  const context = createContext(request, storage, client, config);
  if (!grant.handleToken) {
    throw new UnsupportedGrantTypeError(`Grant does not support token requests: ${grant_type}`);
  }

  return grant.handleToken(context);
}

/**
 * Revocation Endpoint
 * ===================
 * Handles OAuth 2.0 token revocation requests.
 */

/**
 * Processes a token revocation request.
 * Validates the token parameter and revokes the specified token.
 */
async function handleRevokeRequest(request: OAuth2Request, storage: StorageAdapter): Promise<OAuth2Response> {
  const body = parseRequestBody(request);
  const { token } = body;

  if (!token) {
    throw new InvalidRequestError('Missing token parameter');
  }

  // In a real implementation, you would validate the client making the revocation request
  // and ensure they are authorized to revoke this token.
  await storage.revokeToken(token);

  return {
    statusCode: 200,
    headers: {},
    body: {},
    cookies: {},
  };
}

/**
 * Processes a token introspection request.
 * Returns metadata about the specified token.
 */
async function handleIntrospectRequest(request: OAuth2Request, storage: StorageAdapter): Promise<OAuth2Response> {
  const body = parseRequestBody(request);
  const { token } = body;

  if (!token) {
    throw new InvalidRequestError('Missing token parameter');
  }

  const accessToken = await storage.getAccessToken(token);
  const refreshToken = await storage.getRefreshToken(token);

  let active = false;
  let responseBody: Record<string, any> = { active: false };

  if (accessToken) {
    active = accessToken.accessTokenExpiresAt > new Date();
    if (active) {
      responseBody = {
        active: true,
        scope: accessToken.scope,
        client_id: accessToken.clientId,
        username: accessToken.userId,
        exp: Math.floor(accessToken.accessTokenExpiresAt.getTime() / 1000),
      };
    }
  } else if (refreshToken) {
    active = refreshToken.refreshTokenExpiresAt ? refreshToken.refreshTokenExpiresAt > new Date() : false;
    if (active) {
      responseBody = {
        active: true,
        scope: refreshToken.scope,
        client_id: refreshToken.clientId,
        username: refreshToken.userId,
        exp: Math.floor(refreshToken.refreshTokenExpiresAt!.getTime() / 1000),
      };
    }
  }

  return {
    statusCode: 200,
    headers: { 'Content-Type': 'application/json' },
    body: responseBody,
    cookies: {},
  };
}

/**
 * Creates and configures an OAuth 2.0 server instance.
 * Provides a clean, functional interface for handling OAuth 2.0 flows.
 *
 * @example
 * ```typescript
 * const server = createOAuth2Server({
 *   storage: new MyStorageAdapter(),
 *   grants: [createAuthorizationCodeGrant(), clientCredentialsGrant()],
 *   predefinedScopes: ['read', 'write'],
 *   tokenStrategy: createJwtTokenStrategy({ secret: 'my-secret' })
 * });
 * ```
 */
export function createOAuth2Server(config: ServerConfig): OAuth2Server {
  const completeConfig = createCompleteConfig(config);
  const { storage } = completeConfig;

  return {
    authorize: (request: OAuth2Request) => handleAuthorizeRequest(request, storage, completeConfig),
    token: (request: OAuth2Request) => handleTokenRequest(request, storage, completeConfig),
    revoke: (request: OAuth2Request) => handleRevokeRequest(request, storage),
    introspect: (request: OAuth2Request) => handleIntrospectRequest(request, storage),
  };
}

// For backward compatibility
export const createServer = createOAuth2Server;
