// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ClawPowers Commerce. All Rights Reserved.
// See LICENSE in the repository root for license information.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { AgentGuard } from '../../src/guard.js';
import {
  makeKeyPair,
  makePayload,
  makeToken,
  clearNonces,
  exportPublicKeyBase64,
} from '../helpers.js';

/** Minimal mock of Express req/res/next */
function makeMockExpressContext(headers: Record<string, string> = {}) {
  const req = {
    headers,
    ip: '127.0.0.1',
    method: 'GET',
    url: '/test',
    socket: { remoteAddress: '127.0.0.1' },
  };

  const res = {
    _status: 200,
    _body: null as unknown,
    _headers: {} as Record<string, string>,
    status(code: number) {
      this._status = code;
      return this;
    },
    json(body: unknown) {
      this._body = body;
    },
    set(header: string, value: string) {
      this._headers[header] = value;
      return this;
    },
  };

  const next = vi.fn();

  return { req, res, next };
}

describe('guard.express() middleware', () => {
  let keyPair: CryptoKeyPair;
  let pubKeyB64: string;
  let guard: AgentGuard;

  beforeEach(async () => {
    clearNonces();
    keyPair = await makeKeyPair();
    pubKeyB64 = await exportPublicKeyBase64(keyPair.publicKey);
    guard = new AgentGuard({
      jwt: { publicKeys: new Map([['__default__', pubKeyB64]]) },
    });
  });

  it('calls next() and sets req.agent on allow', async () => {
    const payload = makePayload();
    const token = await makeToken(payload, keyPair.privateKey);
    const { req, res, next } = makeMockExpressContext({
      authorization: `Bearer ${token}`,
    });

    const middleware = guard.express();
    await middleware(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect((req as Record<string, unknown>)['agent']).toBeDefined();
    expect(
      ((req as Record<string, unknown>)['agent'] as { agentId: string })
        .agentId,
    ).toBe(payload.agentId);
  });

  it('responds 401 with challenge body when no JWT', async () => {
    const { req, res, next } = makeMockExpressContext({});
    const middleware = guard.express();
    await middleware(req, res, next);

    expect(res._status).toBe(401);
    expect(next).not.toHaveBeenCalled();
    expect((res._body as Record<string, unknown>)?.['error']).toContain(
      'Challenge',
    );
  });

  it('responds 403 when agent is blocked', async () => {
    const blockGuard = new AgentGuard({
      jwt: { publicKeys: new Map([['__default__', pubKeyB64]]) },
      policy: {
        allowVerified: true,
        allowUnverified: 'challenge',
        blockList: ['openai'],
        allowList: [],
      },
    });

    const payload = makePayload({ operatorId: 'openai' });
    const token = await makeToken(payload, keyPair.privateKey);
    const { req, res, next } = makeMockExpressContext({
      authorization: `Bearer ${token}`,
    });

    const middleware = blockGuard.express();
    await middleware(req, res, next);

    expect(res._status).toBe(403);
    expect(next).not.toHaveBeenCalled();
    expect((res._body as Record<string, unknown>)?.['error']).toBe('Forbidden');
  });

  it('responds 429 with Retry-After when rate limited', async () => {
    const rlGuard = new AgentGuard({
      jwt: { publicKeys: new Map([['__default__', pubKeyB64]]) },
      rateLimit: { windowMs: 60000, maxRequests: 1, keyBy: 'agentId' },
    });

    const middleware = rlGuard.express();

    // First request — allowed
    const payload1 = makePayload({ nonce: crypto.randomUUID() });
    const token1 = await makeToken(payload1, keyPair.privateKey);
    const ctx1 = makeMockExpressContext({ authorization: `Bearer ${token1}` });
    await middleware(ctx1.req, ctx1.res, ctx1.next);
    expect(ctx1.next).toHaveBeenCalledOnce();

    // Second request — rate limited
    const payload2 = makePayload({ nonce: crypto.randomUUID() });
    const token2 = await makeToken(payload2, keyPair.privateKey);
    const ctx2 = makeMockExpressContext({ authorization: `Bearer ${token2}` });
    await middleware(ctx2.req, ctx2.res, ctx2.next);

    expect(ctx2.res._status).toBe(429);
    expect(ctx2.next).not.toHaveBeenCalled();
    expect(ctx2.res._headers['Retry-After']).toBeDefined();
  });
});
