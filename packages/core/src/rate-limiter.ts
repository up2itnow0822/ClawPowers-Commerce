// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ClawPowers Commerce. All Rights Reserved.
// See LICENSE in the repository root for license information.

/**
 * Sliding window rate limiter.
 * Works in-memory (Node.js) with an optional KV adapter for Workers/edge.
 */

/** KV adapter interface for Workers / edge environments */
export interface KVAdapter {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
}

export interface RateLimiterConfig {
  /** Time window in milliseconds */
  windowMs: number;
  /** Maximum requests allowed per window */
  maxRequests: number;
  /** Optional KV adapter for distributed rate limiting */
  kv?: KVAdapter;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetMs: number;
}

interface WindowState {
  /** Timestamps of requests within the current window */
  timestamps: number[];
}

/**
 * In-memory sliding window rate limiter.
 *
 * Each call to `check()` records the request timestamp and evicts
 * timestamps that have fallen outside the window.
 */
export class RateLimiter {
  private readonly windowMs: number;
  private readonly maxRequests: number;
  private readonly kv?: KVAdapter;

  /** In-memory state keyed by agent ID */
  private readonly store = new Map<string, WindowState>();

  constructor(config: RateLimiterConfig) {
    this.windowMs = config.windowMs;
    this.maxRequests = config.maxRequests;
    this.kv = config.kv;
  }

  /**
   * Check and record a request for the given agent ID.
   *
   * @param agentId  Agent or operator identifier
   * @returns Rate limit result
   */
  async check(agentId: string): Promise<RateLimitResult> {
    if (this.kv) {
      return this.checkKV(agentId);
    }
    return this.checkMemory(agentId);
  }

  private checkMemory(agentId: string): RateLimitResult {
    const now = Date.now();
    const windowStart = now - this.windowMs;

    let state = this.store.get(agentId);
    if (!state) {
      state = { timestamps: [] };
      this.store.set(agentId, state);
    }

    // Evict timestamps outside the window
    state.timestamps = state.timestamps.filter((t) => t > windowStart);

    const count = state.timestamps.length;

    if (count >= this.maxRequests) {
      // Find when the oldest request will expire
      const oldestTimestamp = state.timestamps[0] ?? now;
      const resetMs = oldestTimestamp + this.windowMs - now;
      return { allowed: false, remaining: 0, resetMs: Math.max(0, resetMs) };
    }

    // Record this request
    state.timestamps.push(now);
    const remaining = this.maxRequests - state.timestamps.length;
    // Reset time is when the oldest timestamp exits the window
    const oldest = state.timestamps[0] ?? now;
    const resetMs = oldest + this.windowMs - now;

    return { allowed: true, remaining, resetMs: Math.max(0, resetMs) };
  }

  private async checkKV(agentId: string): Promise<RateLimitResult> {
    const key = `rate:${agentId}`;
    const now = Date.now();
    const windowStart = now - this.windowMs;

    const raw = await this.kv!.get(key);
    let timestamps: number[] = [];

    if (raw) {
      try {
        timestamps = JSON.parse(raw) as number[];
      } catch {
        timestamps = [];
      }
    }

    // Evict old timestamps
    timestamps = timestamps.filter((t) => t > windowStart);

    const count = timestamps.length;

    if (count >= this.maxRequests) {
      const oldest = timestamps[0] ?? now;
      const resetMs = oldest + this.windowMs - now;
      // Persist (no new timestamp added)
      await this.kv!.put(key, JSON.stringify(timestamps), {
        expirationTtl: Math.ceil(this.windowMs / 1000) + 1,
      });
      return { allowed: false, remaining: 0, resetMs: Math.max(0, resetMs) };
    }

    timestamps.push(now);
    const oldest = timestamps[0] ?? now;
    const resetMs = oldest + this.windowMs - now;

    await this.kv!.put(key, JSON.stringify(timestamps), {
      expirationTtl: Math.ceil(this.windowMs / 1000) + 1,
    });

    return {
      allowed: true,
      remaining: this.maxRequests - timestamps.length,
      resetMs: Math.max(0, resetMs),
    };
  }

  /** Reset rate limit state for a specific agent (useful for testing) */
  reset(agentId: string): void {
    this.store.delete(agentId);
  }

  /** Clear all state (useful for testing) */
  clear(): void {
    this.store.clear();
  }
}
