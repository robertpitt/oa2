/**
 * OAuth 2.0 Token Strategy Implementations
 *
 * This module provides clean, functional implementations of token strategies.
 * Each strategy handles token generation, validation, and lifecycle management
 * with different trade-offs between performance, security, and scalability.
 */

// JWT Token Strategy - Self-contained, stateless tokens
export { createJwtTokenStrategy, type JwtTokenOptions } from './jwt';

// Opaque Token Strategy - Database-persisted random tokens
export { createOpaqueTokenStrategy, type OpaqueTokenOptions } from './opaque';
