/**
 * AWS Lambda Adapter for OAuth 2.0 Server
 *
 * This module provides clean, functional handlers for integrating the OAuth 2.0 server
 * with AWS Lambda and API Gateway. All functions are focused on AWS-specific concerns.
 */

import { APIGatewayProxyHandler, APIGatewayProxyResult, APIGatewayEvent } from 'aws-lambda';
import { OAuth2Request, OAuth2Response, OAuth2Server } from '../types';
import { OAuth2Error } from '../errors';

/**
 * Request Processing
 * ==================
 */

/**
 * Parses cookies from Cookie header.
 * Extracts cookie name-value pairs for OAuth 2.0 state management.
 */
function extractCookies(cookieHeader: string): Record<string, string> {
  const cookies: Record<string, string> = {};

  if (!cookieHeader) {
    return cookies;
  }

  cookieHeader.split(';').forEach((cookie) => {
    const [name, ...rest] = cookie.trim().split('=');
    if (name && rest.length > 0) {
      cookies[name] = rest.join('=');
    }
  });

  return cookies;
}

/**
 * Extracts OAuth2Request from API Gateway event.
 * Handles both JSON and form-urlencoded request bodies.
 *
 * @example
 * ```typescript
 * export const handler: APIGatewayProxyHandler = async (event) => {
 *   const oauth2Request = extractOAuth2Request(event);
 *   const response = await server.token(oauth2Request);
 *   return transformOAuth2Response(response);
 * };
 * ```
 */
export function extractOAuth2Request(event: APIGatewayEvent): OAuth2Request {
  let parsedBody: Record<string, any> | string | undefined;

  if (event.body) {
    const contentType = event.headers['Content-Type'] || event.headers['content-type'] || '';

    // Handle form-urlencoded bodies (common for OAuth2 token requests)
    if (contentType.includes('application/x-www-form-urlencoded')) {
      parsedBody = event.body; // Keep as string for parseRequestBody utility to handle
    } else if (contentType.includes('application/json')) {
      try {
        parsedBody = JSON.parse(event.body);
      } catch (e) {
        parsedBody = event.body; // Fallback to raw string if JSON parsing fails
      }
    } else {
      parsedBody = event.body; // Raw string for other content types
    }
  }

  return {
    path: event.path,
    method: event.httpMethod.toUpperCase() as 'GET' | 'POST',
    headers: event.headers as Record<string, string>,
    query: (event.queryStringParameters ?? {}) as Record<string, string>,
    body: parsedBody,
    cookies: extractCookies(event.headers.Cookie || event.headers.cookie || ''),
  };
}

/**
 * Response Processing
 * ===================
 */

/**
 * Transforms OAuth2Response into API Gateway result.
 * Handles redirects, headers, cookies, and body formatting.
 *
 * @example
 * ```typescript
 * const oauth2Response = await server.authorize(request);
 * return transformOAuth2Response(oauth2Response);
 * ```
 */
export function transformOAuth2Response(response: OAuth2Response): APIGatewayProxyResult {
  const headers = { ...response.headers };

  const result: APIGatewayProxyResult = {
    statusCode: response.statusCode,
    headers,
    body: typeof response.body === 'string' ? response.body : JSON.stringify(response.body),
    isBase64Encoded: false,
  };

  // Handle redirects for authorization endpoint
  if (response.redirect) {
    result.statusCode = 302;
    headers.Location = response.redirect;
    result.body = '';
  }

  // Ensure Content-Type is set for JSON responses
  if (!headers['Content-Type'] && response.body && typeof response.body === 'object') {
    headers['Content-Type'] = 'application/json';
  }

  // Handle cookies if present
  if (response.cookies && Object.keys(response.cookies).length > 0) {
    const cookieStrings = Object.entries(response.cookies).map(([name, value]) => `${name}=${value}`);
    headers['Set-Cookie'] = cookieStrings.join('; ');
  }

  return result;
}

/**
 * Error Handling
 * ==============
 */

/**
 * Transforms OAuth2Error into API Gateway result.
 * Formats errors according to OAuth 2.0 specifications.
 */
export function transformOAuth2Error(error: OAuth2Error): APIGatewayProxyResult {
  return {
    statusCode: error.statusCode || 500,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      error: error.code,
      error_description: error.description,
    }),
    isBase64Encoded: false,
  };
}

/**
 * Generic Handler
 * ===============
 */

/**
 * Shared helper for handling OAuth2 responses with consistent formatting.
 * Provides unified error handling across all Lambda handlers.
 */
async function handleOAuth2Response(
  handler: (request: OAuth2Request) => Promise<OAuth2Response>,
  event: APIGatewayEvent,
): Promise<APIGatewayProxyResult> {
  try {
    const request = extractOAuth2Request(event);
    const response = await handler(request);
    return transformOAuth2Response(response);
  } catch (error) {
    // Handle OAuth2Error instances
    if (error instanceof OAuth2Error) {
      return transformOAuth2Error(error);
    }

    // Handle unexpected errors
    console.error('Unexpected error in OAuth2 handler:', error);
    return {
      statusCode: 500,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        error: 'server_error',
        error_description: 'An unexpected error occurred',
      }),
      isBase64Encoded: false,
    };
  }
}

/**
 * OAuth 2.0 Endpoint Handlers
 * ===========================
 */

/**
 * AWS Lambda handler for OAuth2 authorization requests.
 *
 * @example
 * ```typescript
 * import { createOAuth2Server } from 'oauth';
 * import { apiGatewayAuthorizeHandler } from 'oauth/adapters/aws';
 *
 * const server = createOAuth2Server({ ... });
 * export const authorize = apiGatewayAuthorizeHandler(server);
 * ```
 */
export function apiGatewayAuthorizeHandler(server: OAuth2Server): APIGatewayProxyHandler {
  return async (event) => handleOAuth2Response(server.authorize.bind(server), event);
}

/**
 * AWS Lambda handler for OAuth2 token requests.
 *
 * @example
 * ```typescript
 * const server = createOAuth2Server({ ... });
 * export const token = apiGatewayTokenHandler(server);
 * ```
 */
export function apiGatewayTokenHandler(server: OAuth2Server): APIGatewayProxyHandler {
  return async (event) => handleOAuth2Response(server.token.bind(server), event);
}

/**
 * AWS Lambda handler for OAuth2 revoke requests.
 *
 * @example
 * ```typescript
 * const server = createOAuth2Server({ ... });
 * export const revoke = apiGatewayRevokeHandler(server);
 * ```
 */
export function apiGatewayRevokeHandler(server: OAuth2Server): APIGatewayProxyHandler {
  return async (event) => handleOAuth2Response(server.revoke.bind(server), event);
}

/**
 * AWS Lambda handler for OAuth2 introspect requests.
 *
 * @example
 * ```typescript
 * const server = createOAuth2Server({ ... });
 * export const introspect = apiGatewayIntrospectHandler(server);
 * ```
 */
export function apiGatewayIntrospectHandler(server: OAuth2Server): APIGatewayProxyHandler {
  return async (event) => handleOAuth2Response(server.introspect.bind(server), event);
}
