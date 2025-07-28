import { OAuth2ErrorCode } from './types';

/**
 * Default Descriptions
 */
export const defaultErrorDescriptions: Record<OAuth2ErrorCode, string> = {
  invalid_request:
    'The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.',
  unauthorized_client: 'The client is not authorized to request an authorization code using this method.',
  access_denied: 'The resource owner or authorization server denied the request.',
  unsupported_response_type:
    'The authorization server does not support obtaining an authorization code using this response type.',
  invalid_scope: 'The requested scope is invalid, unknown, or malformed.',
  server_error:
    'The authorization server encountered an unexpected condition that prevented it from fulfilling the request.',
  temporarily_unavailable:
    'The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.',
  invalid_grant:
    'The provided authorization grant (e.g., authorization code, refresh token) or the refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client.',
  unsupported_grant_type: 'The authorization grant type is not supported by the authorization server.',
};

/**
 * Base class for all OAuth2 related errors.
 */
export class OAuth2Error extends Error {
  public readonly code: OAuth2ErrorCode;
  public readonly description?: string;
  public readonly statusCode: number;

  constructor(code: OAuth2ErrorCode, description?: string, statusCode: number = 400) {
    super(`[${code}] ${description || defaultErrorDescriptions[code] || 'Unknown error'}`);
    this.name = 'OAuth2Error';
    this.code = code;
    this.description = description || defaultErrorDescriptions[code] || 'Unknown error';
    this.statusCode = statusCode;
  }
}

/**
 * Represents an 'invalid_request' error as per OAuth2 specification.
 * This error indicates that the request is missing a required parameter,
 * includes an invalid parameter value, includes a parameter more than once,
 * or is otherwise malformed.
 */
export class InvalidRequestError extends OAuth2Error {
  constructor(description?: string) {
    super('invalid_request', description, 400);
    this.name = 'InvalidRequestError';
  }
}

/**
 * Represents an 'unauthorized_client' error as per OAuth2 specification.
 * This error indicates that the client is not authorized to request an authorization
 * code using this method.
 */
export class UnauthorizedClientError extends OAuth2Error {
  constructor(description?: string) {
    super('unauthorized_client', description, 400);
    this.name = 'UnauthorizedClientError';
  }
}

/**
 * Represents an 'access_denied' error as per OAuth2 specification.
 * This error indicates that the resource owner or authorization server denied the request.
 */
export class AccessDeniedError extends OAuth2Error {
  constructor(description?: string) {
    super('access_denied', description, 400);
    this.name = 'AccessDeniedError';
  }
}

/**
 * Represents an 'unsupported_response_type' error as per OAuth2 specification.
 * This error indicates that the authorization server does not support
 * obtaining an authorization code using this response type.
 */
export class UnsupportedResponseTypeError extends OAuth2Error {
  constructor(description?: string) {
    super('unsupported_response_type', description, 400);
    this.name = 'UnsupportedResponseTypeError';
  }
}

/**
 * Represents an 'invalid_scope' error as per OAuth2 specification.
 * This error indicates that the requested scope is invalid, unknown, or malformed.
 */
export class InvalidScopeError extends OAuth2Error {
  constructor(description?: string) {
    super('invalid_scope', description, 400);
    this.name = 'InvalidScopeError';
  }
}

/**
 * Represents a 'server_error' as per OAuth2 specification.
 * This error indicates that the authorization server encountered an unexpected
 * condition that prevented it from fulfilling the request.
 */
export class ServerError extends OAuth2Error {
  constructor(description?: string) {
    super('server_error', description, 500);
    this.name = 'ServerError';
  }
}

/**
 * Represents a 'temporarily_unavailable' error as per OAuth2 specification.
 * This error indicates that the authorization server is currently unable to handle
 * the request due to a temporary overloading or maintenance of the server.
 */
export class TemporarilyUnavailableError extends OAuth2Error {
  constructor(description?: string) {
    super('temporarily_unavailable', description, 503);
    this.name = 'TemporarilyUnavailableError';
  }
}

/**
 * Represents an 'invalid_grant' error as per OAuth2 specification.
 * This error indicates that the provided authorization grant (e.g., authorization code,
 * refresh token) or the refresh token is invalid, expired, revoked, does not match the
 * redirection URI used in the authorization request, or was issued to another client.
 */
export class InvalidGrantError extends OAuth2Error {
  constructor(description?: string) {
    super('invalid_grant', description, 400);
    this.name = 'InvalidGrantError';
  }
}

/**
 * Represents an 'unsupported_grant_type' error as per OAuth2 specification.
 * This error indicates that the authorization grant type is not supported by the
 * authorization server.
 * @see RFC 6749, Section 5.2 Error Response
 */
export class UnsupportedGrantTypeError extends OAuth2Error {
  constructor(description?: string) {
    super('unsupported_grant_type', description, 400);
    this.name = 'UnsupportedGrantTypeError';
  }
}
