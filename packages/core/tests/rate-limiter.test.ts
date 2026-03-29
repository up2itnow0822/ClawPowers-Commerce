import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { RateLimiter } from '../src/rate-limiter.js';

describe('RateLimiter (sliding window)', () => {
  let limiter: RateLimiter;

  beforeEach(() => {
    limiter = new RateLimiter({ windowMs: 1000, maxRequests: 3 });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('allows requests within the limit', async () => {
    const r1 = await limiter.check('agent-1');
    const r2 = await limiter.check('agent-1');
    const r3 = await limiter.check('agent-1');

    expect(r1.allowed).toBe(true);
    expect(r2.allowed).toBe(true);
    expect(r3.allowed).toBe(true);
    expect(r3.remaining).toBe(0);
  });

  it('blocks requests over the limit', async () => {
    await limiter.check('agent-1');
    await limiter.check('agent-1');
    await limiter.check('agent-1');

    const r4 = await limiter.check('agent-1');
    expect(r4.allowed).toBe(false);
    expect(r4.remaining).toBe(0);
    expect(r4.resetMs).toBeGreaterThan(0);
  });

  it('tracks different agents independently', async () => {
    await limiter.check('agent-1');
    await limiter.check('agent-1');
    await limiter.check('agent-1');

    const other = await limiter.check('agent-2');
    expect(other.allowed).toBe(true);
  });

  it('allows requests after the window expires', async () => {
    vi.useFakeTimers();
    const r1 = await limiter.check('agent-1');
    const r2 = await limiter.check('agent-1');
    const r3 = await limiter.check('agent-1');
    expect(r3.allowed).toBe(true);

    const r4 = await limiter.check('agent-1');
    expect(r4.allowed).toBe(false);

    // Advance time beyond window
    vi.advanceTimersByTime(1100);

    const r5 = await limiter.check('agent-1');
    expect(r5.allowed).toBe(true);
  });

  it('returns correct remaining count', async () => {
    const r1 = await limiter.check('agent-x');
    expect(r1.remaining).toBe(2);

    const r2 = await limiter.check('agent-x');
    expect(r2.remaining).toBe(1);

    const r3 = await limiter.check('agent-x');
    expect(r3.remaining).toBe(0);
  });

  it('returns resetMs indicating time to window reset', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(0);

    await limiter.check('agent-reset');
    await limiter.check('agent-reset');
    await limiter.check('agent-reset');
    const blocked = await limiter.check('agent-reset');

    expect(blocked.allowed).toBe(false);
    expect(blocked.resetMs).toBeGreaterThan(0);
    expect(blocked.resetMs).toBeLessThanOrEqual(1000);
  });

  it('reset() clears state for a specific agent', async () => {
    await limiter.check('agent-clear');
    await limiter.check('agent-clear');
    await limiter.check('agent-clear');
    const blocked = await limiter.check('agent-clear');
    expect(blocked.allowed).toBe(false);

    limiter.reset('agent-clear');

    const after = await limiter.check('agent-clear');
    expect(after.allowed).toBe(true);
  });

  it('clear() resets all state', async () => {
    await limiter.check('a1');
    await limiter.check('a1');
    await limiter.check('a1');
    await limiter.check('a2');
    await limiter.check('a2');
    await limiter.check('a2');

    limiter.clear();

    expect((await limiter.check('a1')).allowed).toBe(true);
    expect((await limiter.check('a2')).allowed).toBe(true);
  });
});
