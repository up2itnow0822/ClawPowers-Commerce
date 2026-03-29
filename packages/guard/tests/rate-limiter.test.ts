// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ClawPowers Commerce. All Rights Reserved.
// See LICENSE in the repository root for license information.

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { RateLimiter } from '@clawpowers/core';

describe('RateLimiter in guard context', () => {
  let limiter: RateLimiter;

  beforeEach(() => {
    limiter = new RateLimiter({ windowMs: 5000, maxRequests: 5 });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('allows up to maxRequests in window', async () => {
    for (let i = 0; i < 5; i++) {
      const r = await limiter.check('agent-a');
      expect(r.allowed).toBe(true);
    }
  });

  it('blocks the 6th request', async () => {
    for (let i = 0; i < 5; i++) {
      await limiter.check('agent-b');
    }
    const blocked = await limiter.check('agent-b');
    expect(blocked.allowed).toBe(false);
    expect(blocked.remaining).toBe(0);
  });

  it('sliding window: old timestamps expire', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(0);

    await limiter.check('slide');
    await limiter.check('slide');
    await limiter.check('slide');
    await limiter.check('slide');
    await limiter.check('slide');

    const blocked = await limiter.check('slide');
    expect(blocked.allowed).toBe(false);

    vi.advanceTimersByTime(5100);

    const allowed = await limiter.check('slide');
    expect(allowed.allowed).toBe(true);
  });

  it('IP-keyed rate limiting uses IP as key', async () => {
    const ipLimiter = new RateLimiter({ windowMs: 60000, maxRequests: 2 });

    const r1 = await ipLimiter.check('192.168.1.1');
    const r2 = await ipLimiter.check('192.168.1.1');
    const r3 = await ipLimiter.check('192.168.1.1');

    expect(r1.allowed).toBe(true);
    expect(r2.allowed).toBe(true);
    expect(r3.allowed).toBe(false);

    // Different IP is unaffected
    const r4 = await ipLimiter.check('10.0.0.1');
    expect(r4.allowed).toBe(true);
  });
});
