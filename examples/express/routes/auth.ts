import express, { Request, Response } from 'express';
import { InMemoryStorageAdapter } from '../../../tests/mocks/storage';
import { Client } from '../../../src/types';
import * as crypto from 'crypto';

const router = express.Router();

// Extend Request interface for our auth helpers
declare global {
  namespace Express {
    interface Request {
      login: (userId: string, username: string) => void;
      logout: () => void;
      isAuthenticated: () => boolean;
    }
  }
}

// Demo users (in production, this would be in a database)
const demoUsers = [
  { id: 'user1', username: 'testuser', password: 'password', scopes: ['read', 'write', 'profile'] },
  { id: 'user2', username: 'admin', password: 'admin123', scopes: ['read', 'write', 'profile', 'admin'] },
];

// Temporary storage for authorization requests
const pendingAuthorizations = new Map<string, any>();

export function createAuthRoutes(storage: InMemoryStorageAdapter) {
  // Login page
  router.get('/login', (req: Request, res: Response) => {
    const returnTo = req.query.returnTo as string;
    const error = req.query.error as string;

    res.render('login', {
      layout: false,
      returnTo,
      error: error ? decodeURIComponent(error) : null,
    });
  });

  // Login form submission
  router.post('/login', (req: Request, res: Response) => {
    const { username, password, returnTo } = req.body;

    // Find user
    const user = demoUsers.find((u) => u.username === username && u.password === password);

    if (!user) {
      const error = encodeURIComponent('Invalid username or password');
      return res.redirect(`/auth/login?error=${error}${returnTo ? `&returnTo=${encodeURIComponent(returnTo)}` : ''}`);
    }

    // Log user in
    req.login(user.id, user.username);

    // Redirect to return URL or dashboard
    const redirectUrl = returnTo || '/';
    res.redirect(redirectUrl);
  });

  // Logout
  router.post('/logout', (req: Request, res: Response) => {
    req.logout();
    res.redirect('/');
  });

  // Authorization endpoint (handles OAuth authorize requests)
  router.get('/authorize', async (req: Request, res: Response) => {
    try {
      const { response_type, client_id, redirect_uri, scope, state, code_challenge, code_challenge_method } = req.query;

      // Basic validation
      if (response_type !== 'code') {
        return res.redirect(`${redirect_uri}?error=unsupported_response_type&state=${state}`);
      }

      if (!client_id || !redirect_uri) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing required parameters',
        });
      }

      // Validate client and redirect_uri
      const client = await storage.getClient(client_id as string);
      if (!client) {
        return res.status(400).json({
          error: 'invalid_client',
          error_description: 'Invalid client_id',
        });
      }

      if (!client.redirectUris.includes(redirect_uri as string)) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Invalid redirect_uri',
        });
      }

      // Check if user is authenticated
      if (!req.isAuthenticated()) {
        const returnTo = encodeURIComponent(req.originalUrl);
        return res.redirect(`/auth/login?returnTo=${returnTo}`);
      }

      // Show consent page
      const requestedScopes = (scope as string)?.split(' ') || [];
      const authId = crypto.randomBytes(16).toString('hex');

      // Store authorization request
      pendingAuthorizations.set(authId, {
        client_id,
        redirect_uri,
        scope,
        state,
        code_challenge,
        code_challenge_method,
        userId: req.session!.userId,
        username: req.session!.username,
      });

      // Set expiration for pending authorization (5 minutes)
      setTimeout(
        () => {
          pendingAuthorizations.delete(authId);
        },
        5 * 60 * 1000,
      );

      res.render('consent', {
        layout: false,
        client,
        user: { username: req.session!.username },
        scopes: requestedScopes,
        requested_scope: scope,
        redirect_uri,
        state,
        code_challenge,
        code_challenge_method,
        authId,
      });
    } catch (error) {
      console.error('Authorization error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error',
      });
    }
  });

  // Consent form submission
  router.post('/consent', async (req: Request, res: Response) => {
    try {
      const { decision, client_id, redirect_uri, scope, state, code_challenge, code_challenge_method } = req.body;

      if (decision === 'deny') {
        return res.redirect(
          `${redirect_uri}?error=access_denied&error_description=User denied authorization&state=${state}`,
        );
      }

      // Generate authorization code
      const authCode = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

      // Save authorization code
      await storage.saveAuthorizationCode({
        code: authCode,
        clientId: client_id,
        userId: req.session!.userId!,
        redirectUri: redirect_uri,
        scope: scope,
        expiresAt,
        codeChallenge: code_challenge,
        codeChallengeMethod: code_challenge_method || 'plain',
      });

      // Redirect back to client with authorization code
      const redirectUrl = `${redirect_uri}?code=${authCode}&state=${state}`;
      res.redirect(redirectUrl);
    } catch (error) {
      console.error('Consent error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error',
      });
    }
  });

  return router;
}

export { demoUsers };
