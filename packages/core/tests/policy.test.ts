// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ClawPowers Commerce. All Rights Reserved.
// See LICENSE in the repository root for license information.

import { describe, it, expect } from 'vitest';
import { PolicyEngine, matchGlob, matchesAny } from '../src/policy.js';
import type { PolicyConfig } from '../src/policy.js';
import type { AgentIdentityPayload, ReputationScore } from '../src/types.js';

function makeIdentity(overrides: Partial<AgentIdentityPayload> = {}): AgentIdentityPayload {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: 'https://issuer.example.com',
    sub: 'agent:test-001',
    iat: now,
    exp: now + 3600,
    nonce: crypto.randomUUID(),
    operatorId: 'openai',
    operatorDomain: 'openai.com',
    agentId: 'gpt-agent-001',
    agentVersion: '1.0.0',
    capabilities: ['browse'],
    intent: 'read',
    ...overrides,
  };
}

function makeReputation(score: number): ReputationScore {
  return { score, provider: 'static', lastUpdated: Date.now() };
}

const baseConfig: PolicyConfig = {
  allowVerified: true,
  allowUnverified: 'challenge',
  blockList: [],
  allowList: [],
  minReputationScore: 0,
};

describe('matchGlob', () => {
  it('matches exact strings', () => {
    expect(matchGlob('openai', 'openai')).toBe(true);
    expect(matchGlob('openai', 'anthropic')).toBe(false);
  });

  it('matches wildcard * (any characters)', () => {
    expect(matchGlob('openai-*', 'openai-gpt4')).toBe(true);
    expect(matchGlob('openai-*', 'openai-')).toBe(true);
    expect(matchGlob('openai-*', 'anthropic-claude')).toBe(false);
  });

  it('matches wildcard ? (single character)', () => {
    expect(matchGlob('agent-?', 'agent-1')).toBe(true);
    expect(matchGlob('agent-?', 'agent-12')).toBe(false);
  });

  it('matches * in the middle', () => {
    expect(matchGlob('op*id', 'operatorid')).toBe(true);
    expect(matchGlob('op*id', 'opid')).toBe(true);
  });

  it('matches ** as multiple wildcards', () => {
    expect(matchGlob('*', 'anything-goes')).toBe(true);
  });
});

describe('matchesAny', () => {
  it('returns true if any pattern matches', () => {
    expect(matchesAny(['openai-*', 'anthropic-*'], 'openai-gpt4')).toBe(true);
  });

  it('returns false if no pattern matches', () => {
    expect(matchesAny(['openai-*', 'anthropic-*'], 'cohere-cmd')).toBe(false);
  });

  it('returns false for empty patterns', () => {
    expect(matchesAny([], 'openai')).toBe(false);
  });
});

describe('PolicyEngine', () => {
  const engine = new PolicyEngine();

  it('allows a verified agent with default config', () => {
    const identity = makeIdentity();
    const decision = engine.evaluate(identity, null, baseConfig);
    expect(decision).toBe('allow');
  });

  it('challenges an unverified agent (default: challenge)', () => {
    const decision = engine.evaluate(null, null, baseConfig);
    expect(decision).toBe('challenge');
  });

  it('denies an unverified agent when allowUnverified is deny', () => {
    const config: PolicyConfig = { ...baseConfig, allowUnverified: 'deny' };
    const decision = engine.evaluate(null, null, config);
    expect(decision).toBe('deny');
  });

  it('denies a blocked operator by exact match', () => {
    const config: PolicyConfig = { ...baseConfig, blockList: ['openai'] };
    const identity = makeIdentity({ operatorId: 'openai' });
    const decision = engine.evaluate(identity, null, config);
    expect(decision).toBe('deny');
  });

  it('denies a blocked operator by wildcard', () => {
    const config: PolicyConfig = { ...baseConfig, blockList: ['openai-*'] };
    const identity = makeIdentity({ operatorId: 'openai-evil' });
    const decision = engine.evaluate(identity, null, config);
    expect(decision).toBe('deny');
  });

  it('does NOT deny an operator that does not match blockList', () => {
    const config: PolicyConfig = { ...baseConfig, blockList: ['openai-*'] };
    const identity = makeIdentity({ operatorId: 'anthropic' });
    const decision = engine.evaluate(identity, null, config);
    expect(decision).toBe('allow');
  });

  it('allows an allowListed operator even if verified check would deny', () => {
    const config: PolicyConfig = {
      ...baseConfig,
      allowVerified: false,
      allowList: ['trusted-operator'],
    };
    const identity = makeIdentity({ operatorId: 'trusted-operator' });
    const decision = engine.evaluate(identity, null, config);
    expect(decision).toBe('allow');
  });

  it('allowList wildcard overrides blockList check', () => {
    const config: PolicyConfig = {
      ...baseConfig,
      blockList: ['openai'],
      allowList: ['openai'],
    };
    const identity = makeIdentity({ operatorId: 'openai' });
    // allowList is checked first
    const decision = engine.evaluate(identity, null, config);
    expect(decision).toBe('allow');
  });

  it('denies when allowVerified is false', () => {
    const config: PolicyConfig = { ...baseConfig, allowVerified: false };
    const identity = makeIdentity();
    const decision = engine.evaluate(identity, null, config);
    expect(decision).toBe('deny');
  });

  it('challenges when minReputationScore not met (no score)', () => {
    const config: PolicyConfig = { ...baseConfig, minReputationScore: 50 };
    const identity = makeIdentity();
    const decision = engine.evaluate(identity, null, config);
    expect(decision).toBe('challenge');
  });

  it('challenges when reputation score is below threshold', () => {
    const config: PolicyConfig = { ...baseConfig, minReputationScore: 80 };
    const identity = makeIdentity();
    const rep = makeReputation(40);
    const decision = engine.evaluate(identity, rep, config);
    expect(decision).toBe('challenge');
  });

  it('allows when reputation score meets threshold', () => {
    const config: PolicyConfig = { ...baseConfig, minReputationScore: 50 };
    const identity = makeIdentity();
    const rep = makeReputation(75);
    const decision = engine.evaluate(identity, rep, config);
    expect(decision).toBe('allow');
  });
});
