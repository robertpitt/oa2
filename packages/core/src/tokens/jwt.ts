import jwt from 'jsonwebtoken';
import { Token, Context, TokenStrategy, TokenGenerationParams, StorageAdapter } from '../types';

export interface JwtTokenOptions {
  /** The secret key used to sign and verify JWTs */
  secret: string;
  /** Access token expiration time in seconds */
  accessTokenExpiresIn?: number;
  /** Refresh token expiration time in seconds */
  refreshTokenExpiresIn?: number;
  /** JWT algorithm to use */
  algorithm?: jwt.Algorithm;
  /** Custom issuer for the JWT */
  issuer?: string;
  /** Custom audience for the JWT */
  audience?: string;
}

/**
 * Creates a JWT token payload with common fields.
 * This ensures consistency across access and refresh tokens.
 */
function createTokenPayload(
  params: TokenGenerationParams,
  tokenType: 'access_token' | 'refresh_token',
  expiresAt: Date,
  options: JwtTokenOptions,
): any {
  const { client, userId, scope, metadata } = params;

  return {
    sub: userId,
    client_id: client.id,
    scope,
    token_type: tokenType,
    exp: Math.floor(expiresAt.getTime() / 1000),
    iat: Math.floor(Date.now() / 1000),
    ...(options.issuer && { iss: options.issuer }),
    ...(options.audience && { aud: options.audience }),
    ...(metadata && { metadata }),
  };
}

/**
 * Generates an access token using JWT.
 * Creates a stateless, self-contained token.
 */
async function generateAccessToken(
  params: TokenGenerationParams,
  context: Context,
  options: JwtTokenOptions,
  storage: StorageAdapter,
): Promise<Token> {
  const accessTokenExpiresAt = new Date(Date.now() + (options.accessTokenExpiresIn || 3600) * 1000);

  const payload = createTokenPayload(params, 'access_token', accessTokenExpiresAt, options);
  const accessToken = jwt.sign(payload, options.secret, { algorithm: options.algorithm || 'HS256' });

  const token = {
    accessToken,
    accessTokenExpiresAt,
    scope: params.scope,
    clientId: params.client.id,
    userId: params.userId,
  };

  // Store JWT token for revocation tracking
  await storage.saveToken(token);

  return token;
}

/**
 * Generates a refresh token using JWT.
 * Creates a long-lived token for obtaining new access tokens.
 */
async function generateRefreshToken(
  params: TokenGenerationParams,
  context: Context,
  options: JwtTokenOptions,
  storage: StorageAdapter,
): Promise<Token> {
  const refreshTokenExpiresAt = new Date(Date.now() + (options.refreshTokenExpiresIn || 604800) * 1000);

  const payload = createTokenPayload(params, 'refresh_token', refreshTokenExpiresAt, options);
  const refreshToken = jwt.sign(payload, options.secret, { algorithm: options.algorithm || 'HS256' });

  const token = {
    accessToken: '', // Not applicable for refresh token generation
    accessTokenExpiresAt: new Date(),
    refreshToken,
    refreshTokenExpiresAt,
    scope: params.scope,
    clientId: params.client.id,
    userId: params.userId,
  };

  // Store JWT token for revocation tracking
  await storage.saveToken(token);

  return token;
}

/**
 * Generates both access and refresh tokens in a single operation.
 * More efficient when both tokens are needed.
 */
async function generateTokenPair(
  params: TokenGenerationParams,
  context: Context,
  options: JwtTokenOptions,
  storage: StorageAdapter,
): Promise<Token> {
  const accessTokenExpiresAt = new Date(Date.now() + (options.accessTokenExpiresIn || 3600) * 1000);
  const refreshTokenExpiresAt = new Date(Date.now() + (options.refreshTokenExpiresIn || 604800) * 1000);

  const basePayload = {
    sub: params.userId,
    client_id: params.client.id,
    scope: params.scope,
    iat: Math.floor(Date.now() / 1000),
    ...(options.issuer && { iss: options.issuer }),
    ...(options.audience && { aud: options.audience }),
    ...(params.metadata && { metadata: params.metadata }),
  };

  const accessToken = jwt.sign(
    {
      ...basePayload,
      token_type: 'access_token',
      exp: Math.floor(accessTokenExpiresAt.getTime() / 1000),
    },
    options.secret,
    { algorithm: options.algorithm || 'HS256' },
  );

  const refreshToken = jwt.sign(
    {
      ...basePayload,
      token_type: 'refresh_token',
      exp: Math.floor(refreshTokenExpiresAt.getTime() / 1000),
    },
    options.secret,
    { algorithm: options.algorithm || 'HS256' },
  );

  const token = {
    accessToken,
    accessTokenExpiresAt,
    refreshToken,
    refreshTokenExpiresAt,
    scope: params.scope,
    clientId: params.client.id,
    userId: params.userId,
  };

  // Store JWT token pair for revocation tracking
  await storage.saveToken(token);

  return token;
}

/**
 * Validates a JWT token and extracts its payload.
 * Verifies signature, expiration, and token type.
 */
function validateJwtToken(
  token: string,
  expectedType: 'access_token' | 'refresh_token',
  options: JwtTokenOptions,
): any {
  try {
    const decoded = jwt.verify(token, options.secret, {
      algorithms: [options.algorithm || 'HS256'],
      ...(options.issuer && { issuer: options.issuer }),
      ...(options.audience && { audience: options.audience }),
    }) as any;

    // Verify this is the expected token type
    if (decoded.token_type !== expectedType) {
      return null;
    }

    return decoded;
  } catch (err) {
    return null;
  }
}

/**
 * Validates an access token and returns token information if valid.
 */
async function validateAccessToken(
  accessToken: string,
  context: Context,
  options: JwtTokenOptions,
): Promise<Token | null> {
  const decoded = validateJwtToken(accessToken, 'access_token', options);

  if (!decoded) {
    return null;
  }

  return {
    accessToken,
    accessTokenExpiresAt: new Date(decoded.exp * 1000),
    scope: decoded.scope,
    clientId: decoded.client_id,
    userId: decoded.sub,
  };
}

/**
 * Validates a refresh token and returns token information if valid.
 */
async function validateRefreshToken(
  refreshToken: string,
  context: Context,
  options: JwtTokenOptions,
): Promise<Token | null> {
  const decoded = validateJwtToken(refreshToken, 'refresh_token', options);

  if (!decoded) {
    return null;
  }

  return {
    accessToken: '', // Not applicable for refresh token validation
    accessTokenExpiresAt: new Date(),
    refreshToken,
    refreshTokenExpiresAt: new Date(decoded.exp * 1000),
    scope: decoded.scope,
    clientId: decoded.client_id,
    userId: decoded.sub,
  };
}

/**
 * Creates a JWT Token Strategy.
 *
 * JWT tokens are self-contained and can be validated without database lookups,
 * making them perfect for distributed systems and high-performance scenarios.
 * However, they are still stored for revocation tracking.
 *
 * @param storage The storage adapter for token persistence and revocation tracking
 * @param options JWT token configuration options
 *
 * @example
 * ```typescript
 * const storage = new YourStorageAdapter();
 * const tokenStrategy = createJwtTokenStrategy(storage, {
 *   secret: process.env.JWT_SECRET,
 *   accessTokenExpiresIn: 3600, // 1 hour
 *   refreshTokenExpiresIn: 604800, // 7 days
 *   algorithm: 'HS256',
 *   issuer: 'my-oauth-server',
 *   audience: 'my-api'
 * });
 * ```
 */
export function createJwtTokenStrategy(storage: StorageAdapter, options: JwtTokenOptions): TokenStrategy {
  return {
    generateAccessToken: (params, context) => generateAccessToken(params, context, options, storage),
    generateRefreshToken: (params, context) => generateRefreshToken(params, context, options, storage),
    generateTokenPair: (params, context) => generateTokenPair(params, context, options, storage),
    validateAccessToken: (accessToken, context) => validateAccessToken(accessToken, context, options),
    validateRefreshToken: (refreshToken, context) => validateRefreshToken(refreshToken, context, options),
  };
}
