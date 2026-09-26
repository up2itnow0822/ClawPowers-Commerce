// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ClawPowers Commerce. All Rights Reserved.
// See LICENSE in the repository root for license information.

import { describe, it, expect, beforeEach } from 'vitest';
import { AgentGuard, nextAdapter } from '../../src/guard.js';
import {
  makeKeyPair,
  makePayload,
  makeToken,
  clearNonces,
  exportPublicKeyBase64,
} from '../helpers.js';

describe('guard.nextjs() middleware', () => {
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

  it('returns undefined on allow so Next.js continues the request', async () => {
    const payload = makePayload();
    const token = await makeToken(payload, keyPair.privateKey);
    const middleware = nextAdapter(guard);
    const request = new Request('https://shop.example.com/api/products', {
      headers: { authorization: `Bearer ${token}` },
    });

    const response = await middleware(request);

    expect(response).toBeUndefined();
  });

  it('returns a real 401 Response with challenge JSON when no JWT is present', async () => {
    const middleware = guard.nextjs();
    const request = new Request('https://shop.example.com/api/products');

    const response = await middleware(request);

    expect(response).toBeInstanceOf(Response);
    expect(response?.status).toBe(401);
    expect(response?.headers.get('Content-Type')).toContain('application/json');
    await expect(response?.json()).resolves.toMatchObject({
      error: 'Challenge Required',
      challenge: expect.objectContaining({ type: 'pow' }),
    });
  });

  it('returns a real 403 Response when policy denies the agent', async () => {
    const blockedGuard = new AgentGuard({
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
    const middleware = blockedGuard.nextjs();
    const request = new Request('https://shop.example.com/api/products', {
      headers: { authorization: `Bearer ${token}` },
    });

    const response = await middleware(request);

    expect(response).toBeInstanceOf(Response);
    expect(response?.status).toBe(403);
    await expect(response?.json()).resolves.toMatchObject({
      error: 'Forbidden',
      reason: 'Access denied by policy',
    });
  });
});
