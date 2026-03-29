// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ClawPowers Commerce. All Rights Reserved.
// See LICENSE in the repository root for license information.

/**
 * Policy engine for agent access control decisions.
 */

import type {
  AgentIdentityPayload,
  PolicyDecision,
  ReputationScore,
} from './types.js';

/** Configuration for the policy engine */
export interface PolicyConfig {
  /** Allow agents with a verified identity */
  allowVerified: boolean;
  /** How to handle unverified (no valid JWT) agents */
  allowUnverified: 'challenge' | 'deny';
  /** Glob patterns for operator IDs to block */
  blockList: string[];
  /** Glob patterns for operator IDs to always allow */
  allowList: string[];
  /** Minimum reputation score required (0-100). 0 = no requirement */
  minReputationScore: number;
}

export const defaultPolicyConfig: PolicyConfig = {
  allowVerified: true,
  allowUnverified: 'challenge',
  blockList: [],
  allowList: [],
  minReputationScore: 0,
};

/**
 * Match a value against a glob pattern.
 * Supports '*' (any chars) and '?' (single char) wildcards.
 */
export function matchGlob(pattern: string, value: string): boolean {
  // Escape special regex characters except * and ?
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  // Convert glob wildcards to regex
  const regexStr = escaped.replace(/\*/g, '.*').replace(/\?/g, '.');
  const regex = new RegExp(`^${regexStr}$`);
  return regex.test(value);
}

/**
 * Check if a value matches any pattern in the list.
 */
export function matchesAny(patterns: string[], value: string): boolean {
  return patterns.some((p) => matchGlob(p, value));
}

/**
 * Stateless policy engine. Evaluates agent identity + reputation against config.
 */
export class PolicyEngine {
  /**
   * Evaluate a policy decision.
   *
   * @param identity  Validated agent identity, or null if no valid JWT
   * @param reputation  Reputation score, or null if unavailable
   * @param config  Policy configuration
   * @returns PolicyDecision
   */
  evaluate(
    identity: AgentIdentityPayload | null,
    reputation: ReputationScore | null,
    config: PolicyConfig,
  ): PolicyDecision {
    const merged: PolicyConfig = { ...defaultPolicyConfig, ...config };

    // If no identity, apply unverified policy
    if (!identity) {
      return merged.allowUnverified === 'challenge' ? 'challenge' : 'deny';
    }

    // Check allowList first (bypass all other checks)
    if (
      merged.allowList.length > 0 &&
      matchesAny(merged.allowList, identity.operatorId)
    ) {
      return 'allow';
    }

    // Check blockList
    if (
      merged.blockList.length > 0 &&
      matchesAny(merged.blockList, identity.operatorId)
    ) {
      return 'deny';
    }

    // Check if verified agents are allowed
    if (!merged.allowVerified) {
      return 'deny';
    }

    // Check reputation threshold
    if (merged.minReputationScore > 0) {
      if (!reputation || reputation.score < merged.minReputationScore) {
        return 'challenge';
      }
    }

    return 'allow';
  }
}
