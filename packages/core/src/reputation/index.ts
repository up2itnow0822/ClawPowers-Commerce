// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ClawPowers Commerce. All Rights Reserved.
// See LICENSE in the repository root for license information.

/**
 * Reputation provider interface and implementations.
 */

import type { ReputationScore } from '../types.js';

/** Interface all reputation providers must implement */
export interface ReputationProvider {
  lookup(agentId: string): Promise<ReputationScore | null>;
}

/**
 * HOL (History of Links) registry provider.
 * Fetches agent reputation from the HOL registry API.
 */
export class HOLProvider implements ReputationProvider {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;

  constructor(
    baseUrl = 'https://hol.org/registry/api/v1',
    timeoutMs = 5000,
  ) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.timeoutMs = timeoutMs;
  }

  async lookup(agentId: string): Promise<ReputationScore | null> {
    const url = `${this.baseUrl}/agents/${encodeURIComponent(agentId)}/reputation`;

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);

      const response = await fetch(url, {
        signal: controller.signal,
        headers: { Accept: 'application/json' },
      });

      clearTimeout(timer);

      if (response.status === 404) {
        return null;
      }

      if (!response.ok) {
        throw new Error(`HOL API returned ${response.status}`);
      }

      const data = (await response.json()) as {
        score?: unknown;
        provider?: unknown;
        lastUpdated?: unknown;
      };

      if (
        typeof data.score !== 'number' ||
        typeof data.provider !== 'string' ||
        typeof data.lastUpdated !== 'number'
      ) {
        return null;
      }

      return {
        score: Math.max(0, Math.min(100, data.score)),
        provider: data.provider,
        lastUpdated: data.lastUpdated,
      };
    } catch (err) {
      if (err instanceof Error && err.name === 'AbortError') {
        return null; // Timeout — fail open (caller decides what to do)
      }
      return null;
    }
  }
}

/**
 * ERC-8004 UAID (Universal Agent Identity) resolver stub.
 * In production this would call the agentwallet-sdk UAIDResolver.
 */
export class ERC8004Provider implements ReputationProvider {
  private readonly resolverUrl: string;

  constructor(resolverUrl = 'https://uaid.agentwallet.io/api/v1') {
    this.resolverUrl = resolverUrl.replace(/\/$/, '');
  }

  async lookup(agentId: string): Promise<ReputationScore | null> {
    const url = `${this.resolverUrl}/resolve/${encodeURIComponent(agentId)}`;

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5000);

      const response = await fetch(url, {
        signal: controller.signal,
        headers: { Accept: 'application/json' },
      });

      clearTimeout(timer);

      if (!response.ok) {
        return null;
      }

      const data = (await response.json()) as {
        reputationScore?: unknown;
        lastUpdated?: unknown;
      };

      if (typeof data.reputationScore !== 'number') {
        return null;
      }

      return {
        score: Math.max(0, Math.min(100, data.reputationScore)),
        provider: 'erc8004',
        lastUpdated:
          typeof data.lastUpdated === 'number' ? data.lastUpdated : Date.now(),
      };
    } catch {
      return null;
    }
  }
}

/**
 * Static reputation provider for testing and manual allowlists.
 * Scores are set at construction time and never expire.
 */
export class StaticProvider implements ReputationProvider {
  private readonly scores: Map<string, number>;
  private readonly defaultScore: number | null;

  /**
   * @param scores  Map of agentId → score (0-100)
   * @param defaultScore  Score to return for unknown agents (null = return null)
   */
  constructor(
    scores: Record<string, number> = {},
    defaultScore: number | null = null,
  ) {
    this.scores = new Map(Object.entries(scores));
    this.defaultScore = defaultScore;
  }

  async lookup(agentId: string): Promise<ReputationScore | null> {
    const score = this.scores.get(agentId) ?? this.defaultScore;

    if (score === null) {
      return null;
    }

    return {
      score: Math.max(0, Math.min(100, score)),
      provider: 'static',
      lastUpdated: Date.now(),
    };
  }

  /** Add or update a score at runtime */
  set(agentId: string, score: number): void {
    this.scores.set(agentId, score);
  }
}
