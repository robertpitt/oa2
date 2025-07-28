/**
 * Export a type that list the posible error coes
 */
export type OAuth2ErrorCode =
  | 'invalid_request'
  | 'unauthorized_client'
  | 'access_denied'
  | 'unsupported_response_type'
  | 'invalid_scope'
  | 'server_error'
  | 'temporarily_unavailable'
  | 'invalid_grant'
  | 'unsupported_grant_type';

/**
 * Represents an incoming OAuth2 request, abstracting away framework-specific details.
 * @see RFC 6749, Section 3.1 Authorization Endpoint
 * @see RFC 6749, Section 3.2 Token Endpoint
 */
export interface OAuth2Request {
  /** The path of the request (e.g., '/token'). */
  path: string;

  /** The HTTP method of the request (GET or POST). */
  method: 'GET' | 'POST';

  /** A record of request headers. */
  headers: Record<string, string>;

  /** A record of query parameters. */
  query: Record<string, string>;

  /** The request body, parsed as a record of any type. */
  body?: Record<string, any> | string;

  /** A record of request cookies. */
  cookies: Record<string, string>;
}

/**
 * Represents an outgoing OAuth2 response, abstracting away framework-specific details.
 * @see RFC 6749, Section 3.1.2 Redirection Endpoint
 * @see RFC 6749, Section 4.1.4 Access Token Response
 * @see RFC 6749, Section 5.1 Successful Response
 * @see RFC 6749, Section 5.2 Error Response
 */
export interface OAuth2Response {
  /** The HTTP status code of the response. */
  statusCode: number;

  /** A record of response headers. */
  headers: Record<string, string>;

  /** The response body, which can be a record of any type. */
  body: Record<string, any>;

  /** Optional: A URL to redirect to, if the response is a redirect. */
  redirect?: string;

  /** A record of response cookies. */
  cookies: Record<string, string>;
}

/**
 * Represents an OAuth2 client application.
 * @see RFC 6749, Section 2. Client Registration
 * @see RFC 6749, Section 2.1 Client Types
 * @see RFC 6749, Section 2.2 Client Identifier
 * @see RFC 6749, Section 2.3 Client Authentication
 */
export interface Client {
  /** The unique identifier for the client. */
  id: string;

  /** The client secret, hashed for confidential clients. */
  secret: string;

  /** An array of registered redirect URIs for the client. */
  redirectUris: string[];

  /** An array of allowed OAuth2 grant types for the client. */
  allowedGrants: string[];

  /** An array of scopes that the client is allowed to request. */
  scopes: string[];

  /** Whether the client is allowed to use plain text PKCE. */
  allowPlainTextPkce?: boolean;
}

/**
 * Represents an OAuth2 token (access token and optional refresh token).
 * @see RFC 6749, Section 1.4 Access Token
 * @see RFC 6749, Section 1.5 Refresh Token
 */
export interface Token {
  /** The access token string. */
  accessToken: string;

  /** The expiration date and time of the access token. */
  accessTokenExpiresAt: Date;

  /** Optional: The refresh token string. */
  refreshToken?: string;

  /** Optional: The expiration date and time of the refresh token. */
  refreshTokenExpiresAt?: Date;

  /** The scope of the token. */
  scope: string;

  /** The ID of the client associated with the token. */
  clientId: string;

  /** The ID of the user associated with the token. */
  userId: string;
}

/**
 * Represents an OAuth2 authorization code.
 * @see RFC 6749, Section 1.3.1 Authorization Code
 * @see RFC 7636, Section 4. Protocol (PKCE)
 */
export interface AuthorizationCode {
  /** The authorization code string. */
  code: string;

  /** The expiration date and time of the authorization code. */
  expiresAt: Date;

  /** The redirect URI used in the authorization request. */
  redirectUri: string;

  /** The scope requested during authorization. */
  scope: string;

  /** The ID of the client associated with the authorization code. */
  clientId: string;

  /** The ID of the user associated with the authorization code. */
  userId: string;

  /** The PKCE code challenge. */
  codeChallenge: string;

  /** The PKCE code challenge method (S256 or plain). */
  codeChallengeMethod: 'S256' | 'plain';
}

/**
 * Defines the contract for a storage adapter, responsible for persisting and retrieving OAuth2-related data.
 * This interface abstracts the underlying data storage mechanism.
 */
export interface StorageAdapter<U extends any = any> {
  /**
   * Retrieves a client by its ID.
   * @param clientId The ID of the client.
   * @returns A Promise that resolves to the Client object or null if not found.
   */
  getClient(clientId: string): Promise<Client | null>;

  /**
   * Saves a token (access token and/or refresh token).
   * @param token The Token object to save.
   * @returns A Promise that resolves when the token is saved.
   */
  saveToken(token: Token): Promise<void>;

  /**
   * Retrieves an access token.
   * @param accessToken The access token string.
   * @returns A Promise that resolves to the Token object or null if not found.
   */
  getAccessToken(accessToken: string): Promise<Token | null>;

  /**
   * Retrieves a refresh token.
   * @param refreshToken The refresh token string.
   * @returns A Promise that resolves to the Token object or null if not found.
   */
  getRefreshToken(refreshToken: string): Promise<Token | null>;

  /**
   * Saves an authorization code.
   * @param code The AuthorizationCode object to save.
   * @returns A Promise that resolves when the authorization code is saved.
   */
  saveAuthorizationCode(code: AuthorizationCode): Promise<void>;

  /**
   * Retrieves an authorization code.
   * @param code The authorization code string.
   * @returns A Promise that resolves to the AuthorizationCode object or null if not found.
   */
  getAuthorizationCode(code: string): Promise<AuthorizationCode | null>;

  /**
   * Deletes an authorization code.
   * @param code The authorization code string to delete.
   * @returns A Promise that resolves when the authorization code is deleted.
   */
  deleteAuthorizationCode(code: string): Promise<void>;

  /**
   * Revokes a token (access token or refresh token).
   * @param token The token string to revoke.
   * @returns A Promise that resolves when the token is revoked.
   */
  revokeToken(token: string): Promise<void>;

  /**
   * Retrieves a user by their ID.
   * @param userId The ID of the user.
   * @returns A Promise that resolves to the user object or null if not found.
   */
  getUser(userId: string): Promise<any | null>;

  /**
   * Retrieves a user by their credentials (username and password), if the credentials are invalid, it returns null.
   * @param username The username of the user.
   * @param password The password of the user.
   */
  getUserByCredentials(username: string, password: string): Promise<any | null>;
}

/**
 * Defines the contract for an OAuth2 grant type handler.
 * @see RFC 6749, Section 1.3 Authorization Grant
 */
export interface Grant {
  /**
   * The Grant type identifier (e.g., 'authorization_code', 'client_credentials'), this identifer is unique across all grants.
   * This is used to identify the grant type in requests.
   */
  type: string;

  /**
   * Optional: An array of response types supported by this grant, e.g., ['code', 'token']. This is used to identify the grant type in requests
   * that can support the response type for the `/authorize` endpoint.
   */
  responseTypes?: string[];

  /**
   * Called on the `/authorize` endpoint (e.g., for `authorization_code`).
   */
  handleAuthorization?(context: Context): Promise<OAuth2Response>;

  /**
   * Called on the `/token` endpoint (e.g., for exchanging a code).
   */
  handleToken?(context: Context): Promise<OAuth2Response>;

  /**
   * Optional validation before token issuance (e.g., PKCE, scopes, audience).
   */
  validate?(context: Context): Promise<void>;

  /**
   * Optional hook to resolve scopes (may throw if invalid).
   */
  resolveScopes?(context: Context): Promise<string[]>;
}

/**
 * Parameters for token generation, providing all necessary context and data.
 */
export interface TokenGenerationParams {
  /** The authenticated client */
  client: Client;

  /** The user ID associated with the token */
  userId: string;

  /** The scope for the token */
  scope: string;

  /** Additional metadata that can be included in the token */
  metadata?: Record<string, any>;
}

/**
 * Interface for defining a TokenStrategy, which is responsible for generating and validating tokens.
 * This interface provides a clean abstraction for different token implementations (JWT, opaque, etc.)
 */
export interface TokenStrategy {
  /**
   * Generates a new access token with the specified parameters.
   * @param params Token generation parameters including client, user, and scope information
   * @param context The context containing request details and storage adapter
   * @returns A Promise that resolves to a Token object containing the access token
   */
  generateAccessToken(params: TokenGenerationParams, context: Context): Promise<Token>;

  /**
   * Validates an access token and returns token information if valid.
   * @param accessToken The access token string to validate
   * @param context The context containing request details and storage adapter
   * @returns A Promise that resolves to a Token object if valid, or null if invalid
   */
  validateAccessToken(accessToken: string, context: Context): Promise<Token | null>;

  /**
   * Generates a new refresh token with the specified parameters.
   * @param params Token generation parameters including client, user, and scope information
   * @param context The context containing request details and storage adapter
   * @returns A Promise that resolves to a Token object containing the refresh token
   */
  generateRefreshToken(params: TokenGenerationParams, context: Context): Promise<Token>;

  /**
   * Validates a refresh token and returns token information if valid.
   * @param refreshToken The refresh token string to validate
   * @param context The context containing request details and storage adapter
   * @returns A Promise that resolves to a Token object if valid, or null if invalid
   */
  validateRefreshToken(refreshToken: string, context: Context): Promise<Token | null>;

  /**
   * Optional: Generate both access and refresh tokens in a single call for efficiency.
   * If not implemented, will fall back to calling generateAccessToken and generateRefreshToken separately.
   * @param params Token generation parameters
   * @param context The context containing request details and storage adapter
   * @returns A Promise that resolves to a Token object containing both tokens
   */
  generateTokenPair?(params: TokenGenerationParams, context: Context): Promise<Token>;
}

/**
 * Represents the context for an OAuth2 operation, containing request details, storage adapter, and authenticated client.
 */
export interface Context {
  /** Server Config */
  config: ServerConfig;

  /** The incoming OAuth2 request. */
  request: OAuth2Request;

  /** The storage adapter for data persistence. */
  storage: StorageAdapter;

  /** Optional: The authenticated client associated with the request. */
  client?: Client; // The authenticated client, if available
}

/**
 * Defines the configuration options for the OAuth2 server.
 */
export interface ServerConfig {
  /** The storage adapter to be used by the server. */
  storage: StorageAdapter;
  /** The token strategy to be used by the server. If not provided, defaults to opaque token strategy. */
  tokenStrategy?: TokenStrategy;
  /** An array of supported grant type handlers. */
  grants: Grant[];
  /** An array of predefined, valid scopes supported by the server. */
  predefinedScopes: string[];
  /** Optional: The lifetime of the access token in seconds. Defaults to 3600 (1 hour). */
  accessTokenLifetime?: number;
  /** Optional: The lifetime of the refresh token in seconds. Defaults to 604800 (7 days). */
  refreshTokenLifetime?: number;
  /** Optional: The lifetime of the authorization code in seconds. Defaults to 600 (10 minutes). */
  authorizationCodeLifetime?: number;
  // logger?: Logger; // TODO: Define Logger interface later
}

/**
 * Defines the public interface for the OAuth2 server.
 * @see RFC 6749, Section 1.2 Protocol Flow
 */
export interface OAuth2Server {
  /**
   * Handles an authorization request.
   * @param request The incoming OAuth2 authorization request.
   * @returns A Promise that resolves to an OAuth2Response.
   */
  authorize(request: OAuth2Request): Promise<OAuth2Response>;
  /**
   * Handles a token request.
   * @param request The incoming OAuth2 token request.
   * @returns A Promise that resolves to an OAuth2Response containing the token details.
   */
  token(request: OAuth2Request): Promise<OAuth2Response>;
  /**
   * Handles a token revocation request.
   * @param request The incoming OAuth2 revocation request.
   * @returns A Promise that resolves to an OAuth2Response with a 200 status code upon successful revocation.
   */
  revoke(request: OAuth2Request): Promise<OAuth2Response>;
  /**
   * Handles a token introspection request.
   * @param request The incoming OAuth2 introspection request.
   * @returns A Promise that resolves to an OAuth2Response containing the token's introspection data.
   */
  introspect(request: OAuth2Request): Promise<OAuth2Response>;
}
