import { Client, Token, AuthorizationCode, StorageAdapter } from '../../src/types';

/**
 * An in-memory implementation of the StorageAdapter interface for testing purposes.
 * This adapter stores clients, tokens, authorization codes, and users in JavaScript Maps.
 */
export class InMemoryStorageAdapter implements StorageAdapter {
  private clients: Map<string, Client> = new Map();
  private tokens: Map<string, Token> = new Map();
  private authorizationCodes: Map<string, AuthorizationCode> = new Map();
  private users: Map<string, any> = new Map();

  constructor() {
    // Add a default client for testing
    this.clients.set('test_client', {
      id: 'test_client',
      secret: 'test_secret',
      redirectUris: ['https://client.example.com/cb'],
      allowedGrants: ['authorization_code', 'client_credentials', 'refresh_token'],
      scopes: ['read', 'write', 'offline_access'],
    });
    this.users.set('test_user', { id: 'test_user', username: 'testuser', password: 'password' });
  }

  getUserByCredentials(username: string, password: string): Promise<any | null> {
    const user = Array.from(this.users.values()).find(
      (user) => user.username === username && user.password === password,
    );
    return Promise.resolve(user || null);
  }

  /**
   * Retrieves a client by its ID from memory.
   * @param clientId The ID of the client.
   * @returns A Promise that resolves to the Client object or null if not found.
   * @see RFC 6749, Section 2.2 Client Identifier
   */
  async getClient(clientId: string): Promise<Client | null> {
    return this.clients.get(clientId) || null;
  }

  /**
   * Saves a token (access token and/or refresh token) to memory.
   * @param token The Token object to save.
   * @returns A Promise that resolves when the token is saved.
   * @see RFC 6749, Section 1.4 Access Token
   * @see RFC 6749, Section 1.5 Refresh Token
   */
  async saveToken(token: Token): Promise<void> {
    this.tokens.set(token.accessToken, token);
    if (token.refreshToken) {
      this.tokens.set(token.refreshToken, token);
    }
  }

  /**
   * Retrieves an access token from memory.
   * @param accessToken The access token string.
   * @returns A Promise that resolves to the Token object or null if not found.
   * @see RFC 6749, Section 1.4 Access Token
   */
  async getAccessToken(accessToken: string): Promise<Token | null> {
    const token = this.tokens.get(accessToken);
    if (token && token.accessToken === accessToken) {
      return token;
    }
    return null;
  }

  /**
   * Retrieves a refresh token from memory.
   * @param refreshToken The refresh token string.
   * @returns A Promise that resolves to the Token object or null if not found.
   * @see RFC 6749, Section 1.5 Refresh Token
   */
  async getRefreshToken(refreshToken: string): Promise<Token | null> {
    const token = this.tokens.get(refreshToken);
    if (token && token.refreshToken === refreshToken) {
      return token;
    }
    return null;
  }

  /**
   * Saves an authorization code to memory.
   * @param code The AuthorizationCode object to save.
   * @returns A Promise that resolves when the authorization code is saved.
   * @see RFC 6749, Section 1.3.1 Authorization Code
   */
  async saveAuthorizationCode(code: AuthorizationCode): Promise<void> {
    this.authorizationCodes.set(code.code, code);
  }

  /**
   * Retrieves an authorization code from memory.
   * @param code The authorization code string.
   * @returns A Promise that resolves to the AuthorizationCode object or null if not found.
   * @see RFC 6749, Section 1.3.1 Authorization Code
   */
  async getAuthorizationCode(code: string): Promise<AuthorizationCode | null> {
    return this.authorizationCodes.get(code) || null;
  }

  /**
   * Deletes an authorization code from memory.
   * @param code The authorization code string to delete.
   * @returns A Promise that resolves when the authorization code is deleted.
   * @see RFC 6749, Section 4.1.2 Authorization Response
   * "The client MUST NOT use the authorization code more than once."
   */
  async deleteAuthorizationCode(code: string): Promise<void> {
    this.authorizationCodes.delete(code);
  }

  /**
   * Revokes a token (access token or refresh token) from memory.
   * @param token The token string to revoke.
   * @returns A Promise that resolves when the token is revoked.
   * @see RFC 7009, OAuth 2.0 Token Revocation
   */
  async revokeToken(token: string): Promise<void> {
    // In a real implementation, you'd need to find all tokens associated with this token string
    // and invalidate them. For this in-memory mock, we'll just delete the entry if it exists.
    this.tokens.delete(token);
  }

  /**
   * Retrieves a user by their ID from memory.
   * @param userId The ID of the user.
   * @returns A Promise that resolves to the user object or null if not found.
   * @see RFC 6749, Section 1.1 Roles (Resource Owner)
   */
  async getUser(userId: string): Promise<any | null> {
    return this.users.get(userId) || null;
  }

  /**
   * Saves a client to memory.
   * @param client The Client object to save.
   * @returns A Promise that resolves when the client is saved.
   * @see RFC 6749, Section 2. Client Registration
   */
  async saveClient(client: Client): Promise<void> {
    this.clients.set(client.id, client);
  }
}
