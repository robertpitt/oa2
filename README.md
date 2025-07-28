# OAuth 2.0 Server Library

A comprehensive, RFC-compliant OAuth 2.0 authorization server implementation in TypeScript. This library provides a framework-agnostic OAuth 2.0 server that can be easily integrated with any Node.js web framework or deployed to serverless environments like AWS Lambda.

## Features

### 🔐 OAuth 2.0 Grant Types

- **Authorization Code Grant** with PKCE support (RFC 7636)
- **Client Credentials Grant** for machine-to-machine authentication
- **Refresh Token Grant** for token renewal
- **Resource Owner Password Credentials Grant** (with security warnings)

### 🛡️ Security Features

- PKCE (Proof Key for Code Exchange) support for public clients
- Configurable token lifetimes
- Secure token generation and validation
- RFC-compliant error responses
- Comprehensive scope validation

### 🔧 Token Strategies

- **JWT Token Strategy**: Self-contained tokens with digital signatures
- **Opaque Token Strategy**: Database-persisted random tokens
- Extensible token strategy interface for custom implementations

### 🌐 Framework Integration

- Framework-agnostic core with request/response abstractions
- Built-in AWS Lambda integration
- Easy integration with Express.js, Fastify, or any Node.js framework

### ⚡ Deployment Ready

- TypeScript support with comprehensive type definitions
- Serverless-friendly architecture
- In-memory storage adapter for testing
- Extensible storage interface for production databases

## Installation

```bash
npm install oauth
# or
yarn add oauth
```

## Quick Start

### Basic Server Setup

```typescript
import { createServer, authorizationCodeGrant, clientCredentialsGrant } from 'oauth';
import { InMemoryStorageAdapter } from './storage'; // Your storage implementation

// Create storage adapter
const storage = new InMemoryStorageAdapter();

// Configure the OAuth 2.0 server
const server = createServer({
  storage,
  grants: [authorizationCodeGrant(), clientCredentialsGrant()],
  predefinedScopes: ['read', 'write', 'admin'],
  accessTokenLifetime: 3600, // 1 hour
  refreshTokenLifetime: 604800, // 7 days
});

// Handle authorization requests
app.get('/oauth/authorize', async (req, res) => {
  const request = {
    path: req.path,
    method: req.method,
    headers: req.headers,
    query: req.query,
    body: req.body,
    cookies: req.cookies,
  };

  const response = await server.authorize(request);
  res.status(response.statusCode).json(response.body);
});

// Handle token requests
app.post('/oauth/token', async (req, res) => {
  const request = {
    path: req.path,
    method: req.method,
    headers: req.headers,
    query: req.query,
    body: req.body,
    cookies: req.cookies,
  };

  const response = await server.token(request);
  res.status(response.statusCode).json(response.body);
});
```

### AWS Lambda Integration

```typescript
import { createServer, authorizationCodeGrant, apiGatewayTokenHandler, apiGatewayAuthorizeHandler } from 'oauth';

const server = createServer({
  storage: new YourStorageAdapter(),
  grants: [authorizationCodeGrant()],
  predefinedScopes: ['read', 'write'],
});

// Lambda handlers
export const authorize = apiGatewayAuthorizeHandler(server);
export const token = apiGatewayTokenHandler(server);
export const revoke = apiGatewayRevokeHandler(server);
export const introspect = apiGatewayIntrospectHandler(server);
```

## API Reference

### Server Configuration

#### `ServerConfig`

```typescript
interface ServerConfig {
  storage: StorageAdapter;
  tokenStrategy: TokenStrategy;
  grants: Grant[];
  predefinedScopes: string[];
  accessTokenLifetime?: number; // Default: 3600 (1 hour)
  refreshTokenLifetime?: number; // Default: 604800 (7 days)
  authorizationCodeLifetime?: number; // Default: 600 (10 minutes)
}
```

### Core Methods

#### `server.authorize(request: OAuth2Request): Promise<OAuth2Response>`

Handles OAuth 2.0 authorization requests. Used for the authorization code flow where users are redirected to grant permissions.

**Example Request:**

```
GET /oauth/authorize?response_type=code&client_id=your_client_id&redirect_uri=https://yourapp.com/callback&scope=read&state=xyz&code_challenge=CODE_CHALLENGE&code_challenge_method=S256
```

**Example Response:**

```json
{
  "statusCode": 302,
  "headers": {
    "Location": "https://yourapp.com/callback?code=AUTHORIZATION_CODE&state=xyz"
  }
}
```

#### `server.token(request: OAuth2Request): Promise<OAuth2Response>`

Handles OAuth 2.0 token requests. Used to exchange authorization codes for access tokens or refresh existing tokens.

**Authorization Code Exchange:**

```typescript
const tokenRequest = {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: {
    grant_type: 'authorization_code',
    code: 'AUTHORIZATION_CODE',
    redirect_uri: 'https://yourapp.com/callback',
    client_id: 'your_client_id',
    client_secret: 'your_client_secret',
    code_verifier: 'CODE_VERIFIER',
  },
};

const response = await server.token(tokenRequest);
```

**Response:**

```json
{
  "statusCode": 200,
  "body": {
    "access_token": "ACCESS_TOKEN",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "REFRESH_TOKEN",
    "scope": "read write"
  }
}
```

#### `server.revoke(request: OAuth2Request): Promise<OAuth2Response>`

Handles token revocation requests (RFC 7009).

```typescript
const revokeRequest = {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: {
    token: 'ACCESS_TOKEN_OR_REFRESH_TOKEN',
    token_type_hint: 'access_token', // Optional
  },
};
```

#### `server.introspect(request: OAuth2Request): Promise<OAuth2Response>`

Handles token introspection requests (RFC 7662).

```typescript
const introspectRequest = {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: {
    token: 'ACCESS_TOKEN',
  },
};

const response = await server.introspect(introspectRequest);
// Response includes: { active: true, scope: "read", client_id: "...", exp: 1234567890 }
```

## Grant Types

### Authorization Code Grant with PKCE

The most secure flow for web applications and mobile apps.

```typescript
import { authorizationCodeGrant } from 'oauth';

const grant = authorizationCodeGrant({
  authorizationCodeLifetime: 600, // 10 minutes
  codeVerifierMinLength: 43,
});
```

**Flow:**

1. Client redirects user to `/oauth/authorize`
2. User authenticates and grants permissions
3. Server redirects back with authorization code
4. Client exchanges code for access token at `/oauth/token`

### Client Credentials Grant

For machine-to-machine authentication.

```typescript
import { clientCredentialsGrant } from 'oauth';

const grant = clientCredentialsGrant();
```

**Usage:**

```bash
curl -X POST /oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&scope=read" \
  -u "client_id:client_secret"
```

### Refresh Token Grant

For obtaining new access tokens without user interaction.

```typescript
import { refreshTokenGrant } from 'oauth';

const grant = refreshTokenGrant();
```

**Usage:**

```bash
curl -X POST /oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=REFRESH_TOKEN"
```

## Token Strategies

### JWT Token Strategy

Self-contained tokens that can be validated without database lookups.

```typescript
import { createJwtTokenStrategy } from 'oauth';

const storage = new YourStorageAdapter();
const tokenStrategy = createJwtTokenStrategy(storage, {
  secret: 'your-jwt-secret',
  accessTokenExpiresIn: 3600,
  algorithm: 'HS256',
});
```

### Opaque Token Strategy

Random tokens stored in the database for maximum security.

```typescript
import { createOpaqueTokenStrategy } from 'oauth';

const storage = new YourStorageAdapter();
const tokenStrategy = createOpaqueTokenStrategy(storage, {
  accessTokenExpiresIn: 3600,
  refreshTokenExpiresIn: 604800,
});
```

## Storage Interface

Implement the `StorageAdapter` interface to integrate with your database:

```typescript
interface StorageAdapter {
  getClient(clientId: string): Promise<Client | null>;
  saveToken(token: Token): Promise<void>;
  getAccessToken(accessToken: string): Promise<Token | null>;
  getRefreshToken(refreshToken: string): Promise<Token | null>;
  saveAuthorizationCode(code: AuthorizationCode): Promise<void>;
  getAuthorizationCode(code: string): Promise<AuthorizationCode | null>;
  deleteAuthorizationCode(code: string): Promise<void>;
  revokeToken(token: string): Promise<void>;
  getUser(userId: string): Promise<any | null>;
  getUserByCredentials(username: string, password: string): Promise<any | null>;
}
```

### Example PostgreSQL Storage Adapter

```typescript
import { Pool } from 'pg';
import { StorageAdapter, Client, Token } from 'oauth';

export class PostgreSQLStorageAdapter implements StorageAdapter {
  constructor(private pool: Pool) {}

  async getClient(clientId: string): Promise<Client | null> {
    const result = await this.pool.query('SELECT * FROM oauth_clients WHERE id = $1', [clientId]);
    return result.rows[0] || null;
  }

  async saveToken(token: Token): Promise<void> {
    await this.pool.query(
      'INSERT INTO oauth_tokens (access_token, refresh_token, expires_at, scope, client_id, user_id) VALUES ($1, $2, $3, $4, $5, $6)',
      [token.accessToken, token.refreshToken, token.accessTokenExpiresAt, token.scope, token.clientId, token.userId],
    );
  }

  // ... implement other methods
}
```

## Error Handling

The library provides comprehensive error handling following OAuth 2.0 specifications:

```typescript
import {
  OAuth2Error,
  InvalidRequestError,
  UnauthorizedClientError,
  AccessDeniedError,
  UnsupportedResponseTypeError,
  InvalidScopeError,
  InvalidGrantError,
  UnsupportedGrantTypeError,
} from 'oauth';

try {
  const response = await server.token(request);
} catch (error) {
  if (error instanceof OAuth2Error) {
    console.log('OAuth2 Error:', error.code, error.description);
    // Handle OAuth2-specific errors
  }
}
```

## Security Considerations

### Client Authentication

- **Confidential clients**: Use `client_secret` for authentication
- **Public clients**: Use PKCE for security without secrets
- **Basic authentication**: Supported via `Authorization: Basic` header

### PKCE (Proof Key for Code Exchange)

Always use PKCE for public clients and mobile applications:

```typescript
// Generate code verifier (client-side)
const codeVerifier = generateRandomString(43);
const codeChallenge = base64URLEncode(sha256(codeVerifier));

// Authorization request
GET /oauth/authorize?code_challenge=CODE_CHALLENGE&code_challenge_method=S256&...

// Token request
POST /oauth/token
{
  "code_verifier": "CODE_VERIFIER",
  // ... other parameters
}
```

### Scope Validation

Define and validate scopes to limit access:

```typescript
const server = createServer({
  predefinedScopes: ['read', 'write', 'admin'],
  // ...
});
```

## Testing

The library includes comprehensive test coverage:

```bash
# Run all tests
npm test

# Run integration tests
npm run test:integration

# Run unit tests
npm run test:unit
```

### Mock Storage for Testing

```typescript
import { InMemoryStorageAdapter } from 'oauth/test';

const storage = new InMemoryStorageAdapter();
// Pre-populated with test clients and users
```

## TypeScript Support

Full TypeScript support with comprehensive type definitions:

```typescript
import { OAuth2Server, OAuth2Request, OAuth2Response, Client, Token, Grant, StorageAdapter, ServerConfig } from 'oauth';
```

## Examples

### Complete Express.js Integration

```typescript
import express from 'express';
import { createServer, authorizationCodeGrant } from 'oauth';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const server = createServer({
  storage: new YourStorageAdapter(),
  grants: [authorizationCodeGrant()],
  predefinedScopes: ['read', 'write'],
});

// Authorization endpoint
app.get('/oauth/authorize', async (req, res) => {
  try {
    const response = await server.authorize({
      path: req.path,
      method: req.method as 'GET',
      headers: req.headers as Record<string, string>,
      query: req.query as Record<string, string>,
      body: req.body,
      cookies: req.cookies || {},
    });

    if (response.redirect) {
      res.redirect(response.redirect);
    } else {
      res.status(response.statusCode).json(response.body);
    }
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Token endpoint
app.post('/oauth/token', async (req, res) => {
  try {
    const response = await server.token({
      path: req.path,
      method: req.method as 'POST',
      headers: req.headers as Record<string, string>,
      query: req.query as Record<string, string>,
      body: req.body,
      cookies: req.cookies || {},
    });

    res.status(response.statusCode).json(response.body);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.listen(3000, () => {
  console.log('OAuth 2.0 server running on port 3000');
});
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Releases

This project uses [Changesets](https://github.com/changesets/changesets) for automated versioning and publishing. All packages use **synchronized versioning** - they all get the same version number.

To create a release:

```bash
# 1. Create a changeset describing your changes
yarn changeset

# 2. Commit and push to main
git add . && git commit -m "feat: your feature" && git push

# 3. GitHub Actions will create a Release PR
# 4. Merge the Release PR to publish to npm
```

For more details, see [RELEASING.md](./RELEASING.md).

## License

MIT License - see LICENSE file for details.

## RFC Compliance

This library implements the following OAuth 2.0 and related specifications:

- **RFC 6749**: The OAuth 2.0 Authorization Framework
- **RFC 6750**: The OAuth 2.0 Authorization Framework: Bearer Token Usage
- **RFC 7009**: OAuth 2.0 Token Revocation
- **RFC 7636**: Proof Key for Code Exchange by OAuth Public Clients (PKCE)
- **RFC 7662**: OAuth 2.0 Token Introspection

## Support

- 📖 [Documentation](https://github.com/your-org/oauth/docs)
- 🐛 [Issue Tracker](https://github.com/your-org/oauth/issues)
- 💬 [Discussions](https://github.com/your-org/oauth/discussions)
