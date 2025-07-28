# OAuth 2.0 Examples

Simple examples demonstrating how to use the OAuth 2.0 library.

## Express Server Example

A complete Express.js OAuth 2.0 server with all endpoints.

### Quick Start

```bash
# From project root
npm run build
npx ts-node examples/express/index.ts
```

Visit http://localhost:3000 to see the interactive demo.

### Features

- All 4 OAuth2 endpoints (authorize, token, revoke, introspect)
- All grant types (authorization_code, client_credentials, password, refresh_token)
- Interactive web interface for testing
- Protected API routes with token validation
- Uses main project dependencies (no separate package.json)

### Test Credentials

**Clients:**

- `webapp-client` / `webapp-secret-123`
- `service-client` / `service-secret-456`
- `mobile-client` / `mobile-secret-789`

**User:**

- `testuser` / `password`

### Quick Test

```bash
curl -X POST http://localhost:3000/oauth/token \
  -H "Authorization: Basic $(echo -n 'service-client:service-secret-456' | base64)" \
  -d "grant_type=client_credentials&scope=read"
```
