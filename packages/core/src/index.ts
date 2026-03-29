// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ClawPowers Commerce. All Rights Reserved.
// See LICENSE in the repository root for license information.

// Core types
export type {
  AgentCapability,
  AgentIntent,
  AgentIdentityPayload,
  PolicyDecision,
  PolicyRule,
  ReputationScore,
  AgentProfile,
} from './types.js';

// JWT utilities
export {
  validateAgentJWT,
  signAgentJWT,
  importEd25519PublicKey,
  generateEd25519KeyPair,
  JWTValidationError,
  _clearNonceCache,
} from './jwt.js';

// Policy engine
export {
  PolicyEngine,
  matchGlob,
  matchesAny,
  defaultPolicyConfig,
} from './policy.js';
export type { PolicyConfig } from './policy.js';

// Rate limiter
export { RateLimiter } from './rate-limiter.js';
export type { RateLimiterConfig, RateLimitResult, KVAdapter } from './rate-limiter.js';

// Reputation providers
export {
  HOLProvider,
  ERC8004Provider,
  StaticProvider,
} from './reputation/index.js';
export type { ReputationProvider } from './reputation/index.js';
