/**
 * Express.js Adapter for OAuth 2.0 Server
 *
 * This module provides clean, functional middleware for integrating the OAuth 2.0 server
 * with Express.js applications. All functions are focused on Express-specific concerns.
 */

import { Request, Response, NextFunction } from 'express';
import { OAuth2Request, OAuth2Response, OAuth2Server } from '../types';
import { OAuth2Error } from '../errors';

/**
 * Express OAuth 2.0 Configuration
 * ===============================
 */

export interface ExpressOAuth2Options {
  /** The OAuth2 server instance */
  server: OAuth2Server;
  /** Whether to handle CORS automatically */
  cors?: boolean;
  /** Custom CORS origins (if cors is true) */
  corsOrigins?: string | string[];
  /** Whether to handle preflight OPTIONS requests */
  handlePreflight?: boolean;
}

/**
 * Request/Response Transformation
 * ==============================
 */

/**
 * Converts Express request to OAuth2Request format.
 * Normalizes the request structure for consistent processing.
 */
function expressRequestToOAuth2Request(req: Request): OAuth2Request {
  return {
    path: req.path,
    method: req.method.toUpperCase() as 'GET' | 'POST',
    headers: req.headers as Record<string, string>,
    query: req.query as Record<string, string>,
    body: req.body,
    cookies: req.cookies || {},
  };
}

/**
 * Sends OAuth2Response via Express response.
 * Handles headers, cookies, redirects, and body formatting.
 */
function sendOAuth2Response(res: Response, oauth2Response: OAuth2Response): void {
  // Set headers
  Object.entries(oauth2Response.headers).forEach(([key, value]) => {
    res.set(key, value);
  });

  // Set cookies
  Object.entries(oauth2Response.cookies).forEach(([name, value]) => {
    res.cookie(name, value);
  });

  // Handle redirects
  if (oauth2Response.redirect) {
    res.redirect(oauth2Response.statusCode, oauth2Response.redirect);
    return;
  }

  // Send response
  res.status(oauth2Response.statusCode);

  if (typeof oauth2Response.body === 'string') {
    res.send(oauth2Response.body);
  } else {
    res.json(oauth2Response.body);
  }
}

/**
 * CORS Support
 * ============
 */

/**
 * Handles CORS headers for OAuth2 endpoints.
 * Configures appropriate CORS policies for OAuth 2.0 flows.
 */
function handleCors(req: Request, res: Response, options: ExpressOAuth2Options): void {
  if (!options.cors) return;

  const origin = req.headers.origin;
  const allowedOrigins = Array.isArray(options.corsOrigins)
    ? options.corsOrigins
    : options.corsOrigins
      ? [options.corsOrigins]
      : ['*'];

  if (allowedOrigins.includes('*') || (origin && allowedOrigins.includes(origin))) {
    res.set('Access-Control-Allow-Origin', origin || '*');
  }

  res.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  res.set('Access-Control-Allow-Credentials', 'true');
  res.set('Access-Control-Max-Age', '86400'); // 24 hours
}

/**
 * Generic Handler Factory
 * =======================
 */

/**
 * Creates a generic OAuth2 endpoint handler middleware.
 * Provides consistent error handling and response formatting.
 */
function createOAuth2Handler(handlerMethod: keyof OAuth2Server, options: ExpressOAuth2Options) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // Handle CORS
      handleCors(req, res, options);

      // Handle preflight requests
      if (req.method === 'OPTIONS' && options.handlePreflight !== false) {
        res.status(204).end();
        return;
      }

      // Convert request format
      const oauth2Request = expressRequestToOAuth2Request(req);

      // Call the appropriate OAuth2 server method
      const oauth2Response = await (options.server[handlerMethod] as Function)(oauth2Request);

      // Send response
      sendOAuth2Response(res, oauth2Response);
    } catch (error) {
      if (error instanceof OAuth2Error) {
        // Handle OAuth2-specific errors
        handleCors(req, res, options);
        res.status(error.statusCode).json({
          error: error.code,
          error_description: error.description,
        });
      } else {
        // Pass other errors to Express error handler
        next(error);
      }
    }
  };
}

/**
 * OAuth 2.0 Endpoint Handlers
 * ===========================
 */

/**
 * Express middleware for OAuth2 authorization endpoint.
 */
export function expressAuthorizeHandler(options: ExpressOAuth2Options) {
  return createOAuth2Handler('authorize', options);
}

/**
 * Express middleware for OAuth2 token endpoint.
 */
export function expressTokenHandler(options: ExpressOAuth2Options) {
  return createOAuth2Handler('token', options);
}

/**
 * Express middleware for OAuth2 token revocation endpoint.
 */
export function expressRevokeHandler(options: ExpressOAuth2Options) {
  return createOAuth2Handler('revoke', options);
}

/**
 * Express middleware for OAuth2 token introspection endpoint.
 */
export function expressIntrospectHandler(options: ExpressOAuth2Options) {
  return createOAuth2Handler('introspect', options);
}

/**
 * Express Router Factory
 * =====================
 */

/**
 * Express router factory that sets up all OAuth2 endpoints.
 * Provides a complete OAuth 2.0 server in a single router.
 *
 * @example
 * ```typescript
 * const oauth2Router = createOAuth2Router({
 *   server: myOAuth2Server,
 *   cors: true,
 *   corsOrigins: ['https://myapp.com']
 * });
 *
 * app.use('/oauth', oauth2Router);
 * ```
 */
export function createOAuth2Router(options: ExpressOAuth2Options) {
  const { Router } = require('express');
  const router = Router();

  // Authorization endpoint (GET)
  router.get('/authorize', expressAuthorizeHandler(options));

  // Token endpoint (POST)
  router.post('/token', expressTokenHandler(options));

  // Revocation endpoint (POST)
  router.post('/revoke', expressRevokeHandler(options));

  // Introspection endpoint (POST)
  router.post('/introspect', expressIntrospectHandler(options));

  return router;
}

/**
 * Token Validation Middleware
 * ===========================
 */

/**
 * Express middleware to validate OAuth2 access tokens.
 * Protects routes by requiring valid OAuth 2.0 access tokens.
 *
 * @example
 * ```typescript
 * // Protect a route with required scopes
 * app.get('/api/protected',
 *   validateOAuth2Token({
 *     server: myServer,
 *     scopes: ['read', 'write']
 *   }),
 *   (req, res) => {
 *     // Access req.oauth2Token for token info
 *     res.json({ message: 'Protected resource', user: req.oauth2Token.username });
 *   }
 * );
 * ```
 */
export function validateOAuth2Token(options: { server: OAuth2Server; scopes?: string[]; optional?: boolean }) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const authHeader = req.headers.authorization;

      if (!authHeader) {
        if (options.optional) {
          next();
          return;
        }
        res.status(401).json({
          error: 'invalid_request',
          error_description: 'Missing Authorization header',
        });
        return;
      }

      if (!authHeader.startsWith('Bearer ')) {
        res.status(401).json({
          error: 'invalid_request',
          error_description: 'Invalid Authorization header format',
        });
        return;
      }

      const token = authHeader.substring(7);
      const oauth2Request = expressRequestToOAuth2Request(req);

      // Use introspection to validate the token
      const introspectResponse = await options.server.introspect({
        ...oauth2Request,
        method: 'POST',
        body: { token },
      });

      if (introspectResponse.statusCode !== 200 || !introspectResponse.body.active) {
        res.status(401).json({
          error: 'invalid_token',
          error_description: 'Token is not active',
        });
        return;
      }

      // Check scopes if required
      if (options.scopes && options.scopes.length > 0) {
        const tokenScopes = (introspectResponse.body.scope || '').split(' ');
        const hasRequiredScope = options.scopes.some((scope) => tokenScopes.includes(scope));

        if (!hasRequiredScope) {
          res.status(403).json({
            error: 'insufficient_scope',
            error_description: `Required scopes: ${options.scopes.join(', ')}`,
          });
          return;
        }
      }

      // Attach token information to request
      (req as any).oauth2Token = introspectResponse.body;

      next();
    } catch (error) {
      res.status(500).json({
        error: 'server_error',
        error_description: 'Token validation failed',
      });
    }
  };
}

/**
 * Type Augmentation
 * =================
 */

/**
 * Type augmentation for Express Request to include OAuth2 token information.
 */
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
