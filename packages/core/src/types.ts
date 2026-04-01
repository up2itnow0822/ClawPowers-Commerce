// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ClawPowers Commerce. All Rights Reserved.
// See LICENSE in the repository root for license information.

/**
 * Core type definitions for ClawPowers Commerce agent identity system.
 */

/** Capabilities an agent can claim */
export type AgentCapability =
  | 'browse'
  | 'interact'
  | 'extract'
  | 'transact'
  | 'subscribe';

/** Intents an agent can declare */
export type AgentIntent = 'read' | 'write' | 'purchase' | 'subscribe';

/** JWT payload for agent identity tokens */
export interface AgentIdentityPayload {
  /** Issuer (operator or registry URL) */
  iss: string;
  /** Subject (unique agent identifier) */
  sub: string;
  /** Issued-at timestamp (seconds since epoch) */
  iat: number;
  /** Expiration timestamp (seconds since epoch) */
  exp: number;
  /** Unique nonce to prevent replay attacks */
  nonce: string;
  /** Operator organization ID */
  operatorId: string;
  /** Operator domain */
  operatorDomain: string;
  /** Agent identifier within the operator's namespace */
  agentId: string;
  /** Semantic version of the agent */
  agentVersion: string;
  /** What the agent can do */
  capabilities: AgentCapability[];
  /** What the agent intends to do in this session */
  intent: AgentIntent;
  /** Optional on-chain wallet address */
  walletAddress?: string;
  /** Optional chain identifier (e.g. 'evm:1', 'solana:mainnet') */
  walletChain?: string;
}

/** Policy evaluation outcome */
export type PolicyDecision = 'allow' | 'challenge' | 'deny' | 'rate-limit';

/** A single policy rule */
export interface PolicyRule {
  /** Human-readable name for this rule */
  name: string;
  /** Outcome if this rule matches */
  decision: PolicyDecision;
  /** Glob patterns matching operatorId */
  operatorIdPatterns?: string[];
  /** Required capabilities (any of these) */
  requiredCapabilities?: AgentCapability[];
  /** Required intent */
  requiredIntent?: AgentIntent;
  /** Priority (higher = evaluated first) */
  priority?: number;
}

/** Reputation score from an external or static provider */
export interface ReputationScore {
  /** Score from 0 (untrusted) to 100 (fully trusted) */
  score: number;
  /** Provider that issued this score */
  provider: string;
  /** Unix timestamp (ms) when this score was last refreshed */
  lastUpdated: number;
}

/** Route-level policy for reputation-based access control */
export interface RoutePolicy {
  /** Minimum reputation score required (0-100) */
  minReputation: number;
  /** Optional rate limit override for this route */
  rateLimit?: {
    windowMs: number;
    maxRequests: number;
  };
}

/** Reputation threshold tier */
export interface ReputationThreshold {
  /** Tier name */
  name: string;
  /** Minimum reputation score */
  minScore: number;
  /** Description of what this tier grants */
  description: string;
}

/** Challenge issued to unidentified agents */
export interface AgentChallenge {
  /** Challenge type */
  type: 'pow' | 'captcha' | 'redirect';
  /** Challenge difficulty (for PoW) */
  difficulty?: number;
  /** Challenge nonce */
  nonce: string;
  /** Challenge endpoint to submit response */
  endpoint: string;
  /** Expiration timestamp (ms) */
  expiresAt: number;
}

/** Full profile combining identity, reputation, and rate-limit state */
export interface AgentProfile {
  /** Verified identity payload, or null if unverified */
  identity: AgentIdentityPayload | null;
  /** Reputation score, or null if not available */
  reputation: ReputationScore | null;
  /** Current rate-limit state */
  rateLimitState: {
    /** Requests remaining in the current window */
    remaining: number;
    /** Milliseconds until the window resets */
    resetMs: number;
  };
}
