import { Token, Context, TokenStrategy, TokenGenerationParams, StorageAdapter } from '../types';
import { generateRandomString } from '../utils';

export interface OpaqueTokenOptions {
  /** Access token expiration time in seconds */
  accessTokenExpiresIn?: number;
  /** Refresh token expiration time in seconds */
  refreshTokenExpiresIn?: number;
  /** Length of generated token strings */
  tokenLength?: number;
}

/**
 * Creates a token object with the given parameters.
 * Helper function to ensure consistency across token creation.
 */
function createToken(
  params: TokenGenerationParams,
  accessToken: string,
  accessTokenExpiresAt: Date,
  refreshToken?: string,
  refreshTokenExpiresAt?: Date,
): Token {
  return {
    accessToken,
    accessTokenExpiresAt,
    refreshToken,
    refreshTokenExpiresAt,
    scope: params.scope,
    clientId: params.client.id,
    userId: params.userId,
  };
}

/**
 * Stores a token in the database.
 * Handles both access and refresh tokens.
 */
async function storeToken(token: Token, storage: StorageAdapter): Promise<void> {
  await storage.saveToken(token);
}

/**
 * Validates a token by checking if it exists and is not expired.
 * Returns null if the token is invalid or expired.
 */
async function validateTokenInStorage(
  tokenValue: string,
  storage: StorageAdapter,
  getTokenFn: (token: string) => Promise<Token | null>,
  expiresAtProperty: keyof Token,
): Promise<Token | null> {
  const token = await getTokenFn(tokenValue);

  if (!token) {
    return null;
  }

  // Check if token is expired
  const expiresAt = token[expiresAtProperty] as Date | undefined;
  if (expiresAt && expiresAt <= new Date()) {
    // Optionally revoke expired token
    await storage.revokeToken(tokenValue);
    return null;
  }

  return token;
}

/**
 * Generates an access token using the opaque strategy.
 * Creates a random token and stores it in the database.
 */
async function generateAccessToken(
  params: TokenGenerationParams,
  context: Context,
  options: OpaqueTokenOptions,
): Promise<Token> {
  const accessToken = generateRandomString(options.tokenLength || 32);
  const accessTokenExpiresAt = new Date(Date.now() + (options.accessTokenExpiresIn || 3600) * 1000);

  const token = createToken(params, accessToken, accessTokenExpiresAt);
  await storeToken(token, context.storage);

  return token;
}

/**
 * Generates a refresh token using the opaque strategy.
 * Creates a random token and stores it in the database.
 */
async function generateRefreshToken(
  params: TokenGenerationParams,
  context: Context,
  options: OpaqueTokenOptions,
): Promise<Token> {
  const refreshToken = generateRandomString(options.tokenLength || 32);
  const refreshTokenExpiresAt = new Date(Date.now() + (options.refreshTokenExpiresIn || 604800) * 1000);

  const token = createToken(
    params,
    '', // Not applicable for refresh token generation
    new Date(),
    refreshToken,
    refreshTokenExpiresAt,
  );

  await storeToken(token, context.storage);
  return token;
}

/**
 * Generates both access and refresh tokens in a single operation.
 * More efficient when both tokens are needed.
 */
async function generateTokenPair(
  params: TokenGenerationParams,
  context: Context,
  options: OpaqueTokenOptions,
): Promise<Token> {
  const accessToken = generateRandomString(options.tokenLength || 32);
  const refreshToken = generateRandomString(options.tokenLength || 32);
  const accessTokenExpiresAt = new Date(Date.now() + (options.accessTokenExpiresIn || 3600) * 1000);
  const refreshTokenExpiresAt = new Date(Date.now() + (options.refreshTokenExpiresIn || 604800) * 1000);

  const token = createToken(params, accessToken, accessTokenExpiresAt, refreshToken, refreshTokenExpiresAt);

  await storeToken(token, context.storage);
  return token;
}

/**
 * Validates an access token by looking it up in the database.
 */
async function validateAccessToken(accessToken: string, context: Context): Promise<Token | null> {
  return validateTokenInStorage(
    accessToken,
    context.storage,
    (token) => context.storage.getAccessToken(token),
    'accessTokenExpiresAt',
  );
}

/**
 * Validates a refresh token by looking it up in the database.
 */
async function validateRefreshToken(refreshToken: string, context: Context): Promise<Token | null> {
  return validateTokenInStorage(
    refreshToken,
    context.storage,
    (token) => context.storage.getRefreshToken(token),
    'refreshTokenExpiresAt',
  );
}

/**
 * Creates an Opaque Token Strategy.
 *
 * Opaque tokens are random strings stored in the database. They provide maximum
 * security as tokens can be easily revoked and contain no embedded information.
 * Validation requires database lookups but provides fine-grained control.
 *
 * @example
 * ```typescript
 * const tokenStrategy = createOpaqueTokenStrategy({
 *   accessTokenExpiresIn: 3600, // 1 hour
 *   refreshTokenExpiresIn: 604800, // 7 days
 *   tokenLength: 32
 * });
 * ```
 */
export function createOpaqueTokenStrategy(options: OpaqueTokenOptions = {}): TokenStrategy {
  return {
    generateAccessToken: (params, context) => generateAccessToken(params, context, options),
    generateRefreshToken: (params, context) => generateRefreshToken(params, context, options),
    generateTokenPair: (params, context) => generateTokenPair(params, context, options),
    validateAccessToken: (accessToken, context) => validateAccessToken(accessToken, context),
    validateRefreshToken: (refreshToken, context) => validateRefreshToken(refreshToken, context),
  };
}

// For backward compatibility
export const opaqueTokenStrategy = createOpaqueTokenStrategy;
