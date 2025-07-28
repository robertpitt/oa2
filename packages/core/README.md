# @oa2/core

A comprehensive, RFC-compliant OAuth 2.0 authorization server implementation in TypeScript.

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

## Installation

```bash
npm install @oa2/core
# or
yarn add @oa2/core
# or
pnpm add @oa2/core
```

## Quick Start

```typescript
import { createOAuth2Server, createJwtTokenStrategy, authorizationCodeGrant } from '@oa2/core';

const storage = new YourStorageAdapter();
const server = createOAuth2Server({
  storage,
  tokenStrategy: createJwtTokenStrategy(storage, { secret: 'your-secret' }),
  grants: [authorizationCodeGrant()],
  predefinedScopes: ['read', 'write'],
});
```

## Module Exports

### Main Entry Points

- `@oa2/core` - Main entry point with all exports
- `@oa2/core/server` - Server creation utilities
- `@oa2/core/grants` - OAuth grant implementations
- `@oa2/core/tokens` - Token strategy implementations
- `@oa2/core/adapters` - Framework adapters (Express, AWS Lambda)
- `@oa2/core/errors` - OAuth error classes
- `@oa2/core/types` - TypeScript type definitions
- `@oa2/core/utils` - Utility functions
- `@oa2/core/testing` - Testing utilities (InMemoryStorageAdapter)

### Token Strategies

#### JWT Token Strategy

Self-contained tokens that can be validated without database lookups.

```typescript
import { createJwtTokenStrategy } from '@oa2/core/tokens';

const storage = new YourStorageAdapter();
const tokenStrategy = createJwtTokenStrategy(storage, {
  secret: 'your-jwt-secret',
  accessTokenExpiresIn: 3600,
  algorithm: 'HS256',
});
```

#### Opaque Token Strategy

Random tokens stored in the database for maximum security.

```typescript
import { createOpaqueTokenStrategy } from '@oa2/core/tokens';

const storage = new YourStorageAdapter();
const tokenStrategy = createOpaqueTokenStrategy(storage, {
  accessTokenExpiresIn: 3600,
  refreshTokenExpiresIn: 604800,
});
```

### Framework Adapters

#### Express.js

```typescript
import { createOAuth2Router } from '@oa2/core/adapters';

const oauth2Router = createOAuth2Router({
  server: myOAuth2Server,
  cors: true,
  corsOrigins: ['https://myapp.com'],
});

app.use('/oauth', oauth2Router);
```

#### AWS Lambda

```typescript
import { lambdaAuthorizeHandler, lambdaTokenHandler } from '@oa2/core/adapters';

export const authorize = lambdaAuthorizeHandler({ server: myOAuth2Server });
export const token = lambdaTokenHandler({ server: myOAuth2Server });
```

## Testing

```typescript
import { InMemoryStorageAdapter } from '@oa2/core/testing';

// Use in your tests
const storage = new InMemoryStorageAdapter();
const server = createOAuth2Server({
  storage,
  // ... other config
});
```

## Storage Interface

Implement the `StorageAdapter` interface to integrate with your database:

```typescript
import { StorageAdapter, Client, Token } from '@oa2/core/types';

class MyStorageAdapter implements StorageAdapter {
  async getClient(clientId: string): Promise<Client | null> {
    // Implement client retrieval
  }

  async saveToken(token: Token): Promise<void> {
    // Implement token storage
  }

  // ... implement other required methods
}
```

## Security Considerations

- Use HTTPS in production
- Implement proper client authentication
- Validate redirect URIs carefully
- Use PKCE for public clients
- Implement rate limiting
- Monitor for suspicious activity

## TypeScript Support

This package is written in TypeScript and includes comprehensive type definitions. All APIs are fully typed with proper IntelliSense support.

## License

MIT

## Repository

This package is part of the `@oa2` monorepo. For issues, documentation, and examples, visit:

[GitHub Repository](https://github.com/robertpitt/oa2)
