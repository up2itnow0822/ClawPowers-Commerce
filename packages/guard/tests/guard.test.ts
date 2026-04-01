// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ClawPowers Commerce. All Rights Reserved.
// See LICENSE in the repository root for license information.

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { AgentGuard } from '../src/guard.js';
import { StaticProvider } from '@clawpowers/core';
import {
  makeKeyPair,
  makePayload,
  makeToken,
  clearNonces,
  exportPublicKeyBase64,
} from './helpers.js';

describe('AgentGuard.evaluate()', () => {
  let keyPair: CryptoKeyPair;
  let pubKeyB64: string;

  beforeEach(async () => {
    clearNonces();
    keyPair = await makeKeyPair();
    pubKeyB64 = await exportPublicKeyBase64(keyPair.publicKey);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  function makeGuard(overrides: ConstructorParameters<typeof AgentGuard>[0] = {}) {
    return new AgentGuard({
      jwt: {
        publicKeys: new Map([['__default__', pubKeyB64]]),
      },
      ...overrides,
    });
  }

  it('allows a verified agent with a valid JWT', async () => {
    const guard = makeGuard();
    const payload = makePayload();
    const token = await makeToken(payload, keyPair.privateKey);

    const result = await guard.evaluate({
      headers: { authorization: `Bearer ${token}` },
      method: 'GET',
      url: '/',
    });

    expect(result.decision).toBe('allow');
    expect(result.agent?.agentId).toBe(payload.agentId);
  });

  it('challenges an unverified agent (no JWT)', async () => {
    const guard = makeGuard();

    const result = await guard.evaluate({
      headers: {},
      method: 'GET',
      url: '/',
    });

    expect(result.decision).toBe('challenge');
    expect(result.agent).toBeNull();
  });

  it('denies when allowUnverified is deny and no JWT', async () => {
    const guard = makeGuard({
      policy: {
        allowVerified: true,
        allowUnverified: 'deny',
        blockList: [],
        allowList: [],
      },
    });

    const result = await guard.evaluate({
      headers: {},
      method: 'GET',
      url: '/',
    });

    expect(result.decision).toBe('deny');
  });

  it('denies a blocked operator', async () => {
    const guard = makeGuard({
      policy: {
        allowVerified: true,
        allowUnverified: 'challenge',
        blockList: ['evil-operator'],
        allowList: [],
      },
    });

    const payload = makePayload({ operatorId: 'evil-operator' });
    const token = await makeToken(payload, keyPair.privateKey);

    const result = await guard.evaluate({
      headers: { authorization: `Bearer ${token}` },
      method: 'GET',
      url: '/',
    });

    expect(result.decision).toBe('deny');
  });

  it('denies a blocked operator via wildcard', async () => {
    const guard = makeGuard({
      policy: {
        allowVerified: true,
        allowUnverified: 'challenge',
        blockList: ['evil-*'],
        allowList: [],
      },
    });

    const payload = makePayload({ operatorId: 'evil-corp' });
    const token = await makeToken(payload, keyPair.privateKey);

    const result = await guard.evaluate({
      headers: { authorization: `Bearer ${token}` },
      method: 'GET',
      url: '/',
    });

    expect(result.decision).toBe('deny');
  });

  it('allows an allowListed operator bypassing other checks', async () => {
    const guard = makeGuard({
      policy: {
        allowVerified: true,
        allowUnverified: 'challenge',
        blockList: ['trusted-op'],
        allowList: ['trusted-op'],
      },
    });

    const payload = makePayload({ operatorId: 'trusted-op' });
    const token = await makeToken(payload, keyPair.privateKey);

    const result = await guard.evaluate({
      headers: { authorization: `Bearer ${token}` },
      method: 'GET',
      url: '/',
    });

    expect(result.decision).toBe('allow');
  });

  it('enforces rate limiting', async () => {
    const guard = makeGuard({
      rateLimit: { windowMs: 60000, maxRequests: 2, keyBy: 'agentId' },
    });

    const payload = makePayload({ nonce: crypto.randomUUID() });
    const token1 = await makeToken(payload, keyPair.privateKey);

    clearNonces();
    const r1 = await guard.evaluate({
      headers: { authorization: `Bearer ${token1}` },
      method: 'GET',
      url: '/',
    });
    expect(r1.decision).toBe('allow');

    // 2nd request with new nonce
    const payload2 = makePayload({ nonce: crypto.randomUUID() });
    const token2 = await makeToken(payload2, keyPair.privateKey);
    const r2 = await guard.evaluate({
      headers: { authorization: `Bearer ${token2}` },
      method: 'GET',
      url: '/',
    });
    expect(r2.decision).toBe('allow');

    // 3rd request — rate limited (agent is extracted from JWT but rate limit key is agentId)
    const payload3 = makePayload({ nonce: crypto.randomUUID() });
    const token3 = await makeToken(payload3, keyPair.privateKey);
    const r3 = await guard.evaluate({
      headers: { authorization: `Bearer ${token3}` },
      method: 'GET',
      url: '/',
    });
    expect(r3.decision).toBe('rate-limit');
    expect(r3.rateLimit.remaining).toBe(0);
    expect(r3.rateLimit.resetMs).toBeGreaterThan(0);
  });

  it('denies when reputation is below threshold (403)', async () => {
    const staticProvider = new StaticProvider({ 'gpt-agent-001': 30 });

    const guard = makeGuard({
      reputation: {
        minScore: 70,
        provider: staticProvider,
        cacheTtlMs: 300000,
      },
    });

    const payload = makePayload();
    const token = await makeToken(payload, keyPair.privateKey);

    const result = await guard.evaluate({
      headers: { authorization: `Bearer ${token}` },
      method: 'GET',
      url: '/',
    });

    // Agent is identified but reputation too low → deny (403), not challenge (401)
    expect(result.decision).toBe('deny');
    expect(result.agent).not.toBeNull();
  });

  it('allows when reputation score meets threshold', async () => {
    const staticProvider = new StaticProvider({ 'gpt-agent-001': 90 });

    const guard = makeGuard({
      reputation: {
        minScore: 70,
        provider: staticProvider,
        cacheTtlMs: 300000,
      },
    });

    const payload = makePayload();
    const token = await makeToken(payload, keyPair.privateKey);

    const result = await guard.evaluate({
      headers: { authorization: `Bearer ${token}` },
      method: 'GET',
      url: '/',
    });

    expect(result.decision).toBe('allow');
  });

  it('extracts token from X-Agent-Identity header', async () => {
    const guard = makeGuard();
    const payload = makePayload();
    const token = await makeToken(payload, keyPair.privateKey);

    const result = await guard.evaluate({
      headers: { 'x-agent-identity': token },
      method: 'GET',
      url: '/',
    });

    expect(result.decision).toBe('allow');
    expect(result.agent?.agentId).toBe(payload.agentId);
  });

  it('triggers onAllow callback', async () => {
    const onAllow = vi.fn();
    const guard = makeGuard({ logging: { onAllow } });

    const payload = makePayload();
    const token = await makeToken(payload, keyPair.privateKey);

    await guard.evaluate({
      headers: { authorization: `Bearer ${token}` },
      method: 'GET',
      url: '/',
    });

    expect(onAllow).toHaveBeenCalledOnce();
  });

  it('triggers onDeny callback', async () => {
    const onDeny = vi.fn();
    const guard = makeGuard({
      policy: {
        allowVerified: true,
        allowUnverified: 'challenge',
        blockList: ['openai'],
        allowList: [],
      },
      logging: { onDeny },
    });

    const payload = makePayload({ operatorId: 'openai' });
    const token = await makeToken(payload, keyPair.privateKey);

    await guard.evaluate({
      headers: { authorization: `Bearer ${token}` },
      method: 'GET',
      url: '/',
    });

    expect(onDeny).toHaveBeenCalledOnce();
  });

  it('triggers onChallenge callback for unverified', async () => {
    const onChallenge = vi.fn();
    const guard = makeGuard({ logging: { onChallenge } });

    await guard.evaluate({ headers: {}, method: 'GET', url: '/' });

    expect(onChallenge).toHaveBeenCalledOnce();
  });

  it('handles invalid request shape gracefully', async () => {
    const guard = makeGuard();
    // @ts-expect-error intentionally bad
    const result = await guard.evaluate({ bad: 'data' });
    expect(result.decision).toBe('deny');
  });

  // ── Route-based reputation tier tests ──────────────────────────────────

  it('allows any agent on browse route (minReputation: 0)', async () => {
    const guard = new AgentGuard({
      jwt: { publicKeys: new Map([['__default__', pubKeyB64]]) },
      routes: {
        '/api/browse/*': { minReputation: 0 },
        '/api/interact/*': { minReputation: 25 },
        '/api/transact/*': { minReputation: 50 },
        '/api/premium/*': { minReputation: 75 },
      },
      reputation: { minScore: 0, provider: new StaticProvider({}, 10), cacheTtlMs: 300000 },
    });

    const payload = makePayload();
    const token = await makeToken(payload, keyPair.privateKey);

    const result = await guard.evaluate({
      headers: { authorization: `Bearer ${token}` },
      method: 'GET',
      url: '/api/browse/products',
    });

    expect(result.decision).toBe('allow');
    expect(result.matchedRoute).toBe('/api/browse/*');
  });

  it('denies agent with low reputation on interact route', async () => {
    const guard = new AgentGuard({
      jwt: { publicKeys: new Map([['__default__', pubKeyB64]]) },
      routes: {
        '/api/browse/*': { minReputation: 0 },
        '/api/interact/*': { minReputation: 25 },
        '/api/transact/*': { minReputation: 50 },
        '/api/premium/*': { minReputation: 75 },
      },
      reputation: { minScore: 0, provider: new StaticProvider({ 'gpt-agent-001': 10 }), cacheTtlMs: 300000 },
    });

    const payload = makePayload();
    const token = await makeToken(payload, keyPair.privateKey);

    const result = await guard.evaluate({
      headers: { authorization: `Bearer ${token}` },
      method: 'POST',
      url: '/api/interact/chat',
    });

    expect(result.decision).toBe('deny');
    expect(result.matchedRoute).toBe('/api/interact/*');
  });

  it('allows agent with sufficient reputation on transact route', async () => {
    const guard = new AgentGuard({
      jwt: { publicKeys: new Map([['__default__', pubKeyB64]]) },
      routes: {
        '/api/browse/*': { minReputation: 0 },
        '/api/interact/*': { minReputation: 25 },
        '/api/transact/*': { minReputation: 50 },
        '/api/premium/*': { minReputation: 75 },
      },
      reputation: { minScore: 0, provider: new StaticProvider({ 'gpt-agent-001': 60 }), cacheTtlMs: 300000 },
    });

    const payload = makePayload();
    const token = await makeToken(payload, keyPair.privateKey);

    const result = await guard.evaluate({
      headers: { authorization: `Bearer ${token}` },
      method: 'POST',
      url: '/api/transact/order',
    });

    expect(result.decision).toBe('allow');
    expect(result.matchedRoute).toBe('/api/transact/*');
  });

  it('denies agent below premium threshold', async () => {
    const guard = new AgentGuard({
      jwt: { publicKeys: new Map([['__default__', pubKeyB64]]) },
      routes: {
        '/api/browse/*': { minReputation: 0 },
        '/api/interact/*': { minReputation: 25 },
        '/api/transact/*': { minReputation: 50 },
        '/api/premium/*': { minReputation: 75 },
      },
      reputation: { minScore: 0, provider: new StaticProvider({ 'gpt-agent-001': 60 }), cacheTtlMs: 300000 },
    });

    const payload = makePayload();
    const token = await makeToken(payload, keyPair.privateKey);

    const result = await guard.evaluate({
      headers: { authorization: `Bearer ${token}` },
      method: 'GET',
      url: '/api/premium/analytics',
    });

    expect(result.decision).toBe('deny');
    expect(result.matchedRoute).toBe('/api/premium/*');
  });

  it('allows premium agent on premium route', async () => {
    const guard = new AgentGuard({
      jwt: { publicKeys: new Map([['__default__', pubKeyB64]]) },
      routes: {
        '/api/browse/*': { minReputation: 0 },
        '/api/premium/*': { minReputation: 75 },
      },
      reputation: { minScore: 0, provider: new StaticProvider({ 'gpt-agent-001': 90 }), cacheTtlMs: 300000 },
    });

    const payload = makePayload();
    const token = await makeToken(payload, keyPair.privateKey);

    const result = await guard.evaluate({
      headers: { authorization: `Bearer ${token}` },
      method: 'GET',
      url: '/api/premium/data',
    });

    expect(result.decision).toBe('allow');
  });

  it('challenges unidentified agent on any route (401)', async () => {
    const guard = new AgentGuard({
      jwt: { publicKeys: new Map([['__default__', pubKeyB64]]) },
      routes: {
        '/api/browse/*': { minReputation: 0 },
        '/api/premium/*': { minReputation: 75 },
      },
    });

    const result = await guard.evaluate({
      headers: {},
      method: 'GET',
      url: '/api/premium/data',
    });

    expect(result.decision).toBe('challenge');
    expect(result.agent).toBeNull();
  });

  it('falls back to global minScore for unmatched routes', async () => {
    const guard = new AgentGuard({
      jwt: { publicKeys: new Map([['__default__', pubKeyB64]]) },
      routes: {
        '/api/browse/*': { minReputation: 0 },
      },
      reputation: { minScore: 50, provider: new StaticProvider({ 'gpt-agent-001': 30 }), cacheTtlMs: 300000 },
    });

    const payload = makePayload();
    const token = await makeToken(payload, keyPair.privateKey);

    const result = await guard.evaluate({
      headers: { authorization: `Bearer ${token}` },
      method: 'GET',
      url: '/api/other/endpoint',
    });

    expect(result.decision).toBe('deny');
    expect(result.matchedRoute).toBeUndefined();
  });

  it('filters by issuerAllowList', async () => {
    const guard = makeGuard({
      jwt: {
        publicKeys: new Map([['__default__', pubKeyB64]]),
        issuerAllowList: ['https://trusted-issuer.com'],
      },
    });

    // Token from untrusted issuer
    const payload = makePayload({ iss: 'https://evil-issuer.com' });
    const token = await makeToken(payload, keyPair.privateKey);

    const result = await guard.evaluate({
      headers: { authorization: `Bearer ${token}` },
      method: 'GET',
      url: '/',
    });

    // Should be treated as no valid JWT → challenge
    expect(result.decision).toBe('challenge');
  });
});
