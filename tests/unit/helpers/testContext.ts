import { Context, OAuth2Request, StorageAdapter, Client, ServerConfig } from '../../../src/types';
import { opaqueTokenStrategy } from '../../../src/tokens';

/**
 * Helper function to create a properly structured Context for unit tests
 */
export function createTestContext(
  request: OAuth2Request,
  storage: StorageAdapter,
  client?: Client,
  configOverrides?: Partial<ServerConfig>,
): Context {
  const defaultConfig: ServerConfig = {
    storage,
    tokenStrategy: opaqueTokenStrategy({
      accessTokenExpiresIn: 3600,
      refreshTokenExpiresIn: 604800,
    }),
    grants: [],
    predefinedScopes: ['read', 'write', 'offline_access'],
    accessTokenLifetime: 3600,
    refreshTokenLifetime: 604800,
    authorizationCodeLifetime: 600,
    ...configOverrides,
  };

  return {
    request,
    storage,
    client,
    config: defaultConfig,
  };
}
