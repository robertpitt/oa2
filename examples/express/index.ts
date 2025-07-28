import express, { Request, Response } from 'express';
import cookieParser from 'cookie-parser';
import hbs from 'hbs';
import path from 'path';
import { createOAuth2Server } from '../../src/server';
import { createOAuth2Router, validateOAuth2Token } from '../../src/adapters/express';
import { authorizationCodeGrant, clientCredentialsGrant, passwordGrant, refreshTokenGrant } from '../../src/grants';
import { InMemoryStorageAdapter } from '../../tests/mocks/storage';
import { hashClientSecret } from '../../src/utils';
import { Client, OAuth2Server } from '../../src/types';
import { sessionMiddleware } from './middleware/session';
import { createAuthRoutes } from './routes/auth';
import { jsonWebTokenStrategy } from '../../src/tokens/jwt';

/**
 * Simple Express.js OAuth 2.0 Server Example (TypeScript)
 *
 * Run with: npx ts-node examples/express/index.ts
 *
 * This example demonstrates all OAuth2 endpoints:
 * - GET  /oauth/authorize   - Authorization endpoint
 * - POST /oauth/token       - Token endpoint
 * - POST /oauth/revoke      - Token revocation
 * - POST /oauth/introspect  - Token introspection
 */

const app = express();
const PORT = process.env.PORT || 3000;

// Configure Handlebars
app.set('view engine', 'hbs');
app.set('views', path.join(__dirname, 'views'));
hbs.registerPartials(path.join(__dirname, 'views/partials'));

// Register Handlebars helpers
hbs.registerHelper('eq', function (a: any, b: any) {
  return a === b;
});

hbs.registerHelper('json', function (context: any) {
  return JSON.stringify(context, null, 2);
});

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(sessionMiddleware);

// Set up storage and example data
const storage = new InMemoryStorageAdapter();

async function initializeData(): Promise<void> {
  // Example clients
  const webClient: Client = {
    id: 'webapp-client',
    secret: 'webapp-secret-123',
    redirectUris: ['http://localhost:3000/callback', 'http://localhost:3001/callback'],
    allowedGrants: ['authorization_code', 'refresh_token'],
    scopes: ['read', 'write', 'admin'],
  };

  const { hashedSecret } = hashClientSecret('service-secret-456');
  const serviceClient: Client = {
    id: 'service-client',
    secret: hashedSecret,
    redirectUris: [],
    allowedGrants: ['client_credentials'],
    scopes: ['read', 'write'],
  };

  const mobileClient: Client = {
    id: 'mobile-client',
    secret: 'mobile-secret-789',
    redirectUris: [],
    allowedGrants: ['password', 'refresh_token'],
    scopes: ['read', 'profile'],
  };

  await storage.saveClient(webClient);
  await storage.saveClient(serviceClient);
  await storage.saveClient(mobileClient);

  // Example user (using storage adapter's built-in user for demo)
  // The InMemoryStorageAdapter already has a test user: testuser / password
  console.log('✅ Example data initialized');
}

// Create OAuth2 server
const oauth2Server: OAuth2Server = createOAuth2Server({
  storage,
  grants: [authorizationCodeGrant(), clientCredentialsGrant(), passwordGrant(), refreshTokenGrant()],
  tokenStrategy: jsonWebTokenStrategy({
    secret: 'secret',
  }),
  predefinedScopes: ['read', 'write', 'admin', 'profile'],
  accessTokenLifetime: 3600,
  refreshTokenLifetime: 604800,
});

// Mount authentication routes (includes custom /oauth/authorize)
app.use('/auth', createAuthRoutes(storage));

// Mount OAuth2 endpoints (excluding authorize which is handled by auth routes)
const oauth2Router = createOAuth2Router({
  server: oauth2Server,
  cors: true,
  corsOrigins: ['http://localhost:3000', 'http://localhost:3001'],
});

// Remove the authorize endpoint from OAuth router since we handle it in auth routes
app.use('/oauth', (req, res, next) => {
  if (req.path === '/authorize' && req.method === 'GET') {
    // Redirect to our custom authorize handler
    return res.redirect('/auth/authorize' + (req.url.substring(req.path.length) || ''));
  }
  oauth2Router(req, res, next);
});

// Enhanced home page with authentication
app.get('/', (req: Request, res: Response) => {
  const isAuth = (req as any).isAuthenticated();
  const user = isAuth ? { username: req.session?.username } : null;

  res.render('home', {
    layout: false,
    user,
  });
});

// Authorization callback
app.get('/callback', async (req: Request, res: Response) => {
  const { code, state, error, error_description } = req.query;

  if (error) {
    return res.render('callback', {
      layout: false,
      error,
      error_description,
      state,
    });
  }

  if (!code) {
    return res.render('callback', {
      layout: false,
    });
  }

  try {
    // Exchange code for token
    const response = await fetch(`http://localhost:${PORT}/oauth/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: 'Basic ' + Buffer.from('webapp-client:webapp-secret-123').toString('base64'),
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code as string,
        redirect_uri: `http://localhost:${PORT}/callback`,
        code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
      }),
    });

    const tokenData = await response.json();

    res.render('callback', {
      layout: false,
      tokenData: JSON.stringify(tokenData, null, 2),
      state,
    });
  } catch (error: any) {
    res.render('callback', {
      layout: false,
      error: 'token_exchange_failed',
      error_description: error.message,
    });
  }
});

// Extend Express Request type for OAuth2 token
declare global {
  namespace Express {
    interface Request {
      oauth2Token?: {
        active: boolean;
        scope?: string;
        client_id?: string;
        username?: string;
        exp?: number;
      };
    }
  }
}

// Protected API examples
app.get(
  '/api/profile',
  validateOAuth2Token({ server: oauth2Server, scopes: ['profile'] }),
  (req: Request, res: Response) => {
    res.json({
      message: 'Protected Profile Data (TypeScript)',
      user: {
        id: req.oauth2Token?.username || 'unknown',
        name: 'Demo User',
        email: 'demo@example.com',
      },
      token_info: {
        scope: req.oauth2Token?.scope,
        client_id: req.oauth2Token?.client_id,
        expires_at: req.oauth2Token?.exp,
      },
      timestamp: new Date().toISOString(),
    });
  },
);

app.get('/api/data', validateOAuth2Token({ server: oauth2Server, scopes: ['read'] }), (req: Request, res: Response) => {
  interface DataItem {
    id: number;
    name: string;
    value: string;
  }

  const data: DataItem[] = [
    { id: 1, name: 'Item 1', value: 'Value 1' },
    { id: 2, name: 'Item 2', value: 'Value 2' },
  ];

  res.json({
    message: 'Protected Data (TypeScript)',
    data,
    token_info: {
      scope: req.oauth2Token?.scope,
      client_id: req.oauth2Token?.client_id,
    },
    timestamp: new Date().toISOString(),
  });
});

// Start server
async function startServer(): Promise<void> {
  try {
    await initializeData();

    app.listen(PORT, () => {
      console.log(`
🚀 OAuth 2.0 TypeScript Server running on http://localhost:${PORT}

📋 Endpoints:
   GET  /oauth/authorize
   POST /oauth/token  
   POST /oauth/revoke
   POST /oauth/introspect

🧪 Test credentials:
   webapp-client / webapp-secret-123
   service-client / service-secret-456  
   mobile-client / mobile-secret-789
   testuser / password

💡 Quick test:
   curl -X POST http://localhost:${PORT}/oauth/token \\
     -H "Authorization: Basic $(echo -n 'service-client:service-secret-456' | base64)" \\
     -d "grant_type=client_credentials&scope=read"
      `);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

startServer();
