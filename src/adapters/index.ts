/**
 * Framework Adapters for OAuth 2.0 Server
 *
 * This module provides clean, functional adapters for integrating the OAuth 2.0 server
 * with popular frameworks and platforms. Each adapter is focused on framework-specific
 * concerns while maintaining a consistent, functional API.
 */

// Express.js Adapter - Middleware and helpers for Express applications
export {
  expressAuthorizeHandler,
  expressTokenHandler,
  expressRevokeHandler,
  expressIntrospectHandler,
  createOAuth2Router,
  validateOAuth2Token,
  type ExpressOAuth2Options,
} from './express';

// AWS Lambda Adapter - Handlers for API Gateway integration
export {
  extractOAuth2Request,
  transformOAuth2Response,
  transformOAuth2Error,
  apiGatewayAuthorizeHandler,
  apiGatewayTokenHandler,
  apiGatewayRevokeHandler,
  apiGatewayIntrospectHandler,
} from './aws';
