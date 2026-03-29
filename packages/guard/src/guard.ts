/**
 * AgentGuard — core agent access control class.
 */

import { z } from 'zod';
import {
  validateAgentJWT,
  PolicyEngine,
  RateLimiter,
  HOLProvider,
  ERC8004Provider,
  StaticProvider,
} from '@clawpowers/core';
import type {
  AgentIdentityPayload,
  PolicyDecision,
  ReputationScore,
  ReputationProvider,
} from '@clawpowers/core';

// ──────────────────────────────────────────────────────────────────────────────
// Request / Result schemas
// ──────────────────────────────────────────────────────────────────────────────

export const GuardRequestSchema = z.object({
  headers: z.record(z.string(), z.string()),
  ip: z.string().optional(),
  method: z.string(),
  url: z.string(),
});

export type GuardRequest = z.infer<typeof GuardRequestSchema>;

export interface GuardResult {
  decision: PolicyDecision;
  agent: AgentIdentityPayload | null;
  reputation: ReputationScore | null;
  rateLimit: {
    remaining: number;
    resetMs: number;
  };
}

// ──────────────────────────────────────────────────────────────────────────────
// Config
// ──────────────────────────────────────────────────────────────────────────────

export interface GuardConfig {
  policy: {
    allowVerified: boolean;
    allowUnverified: 'challenge' | 'deny';
    blockList: string[];
    allowList: string[];
  };
  reputation: {
    minScore: number;
    provider: 'hol' | 'erc8004' | 'static' | ReputationProvider;
    cacheTtlMs: number;
  };
  rateLimit: {
    windowMs: number;
    maxRequests: number;
    keyBy: 'agentId' | 'operatorId' | 'ip';
  };
  jwt: {
    publicKeys: Map<string, string> | (() => Promise<Map<string, string>>);
    issuerAllowList?: string[];
  };
  challenge?: {
    type: 'pow' | 'captcha' | 'redirect';
    difficulty?: number;
  };
  logging: {
    onAllow?: (agent: AgentIdentityPayload, req: unknown) => void;
    onDeny?: (reason: string, req: unknown) => void;
    onChallenge?: (agent: AgentIdentityPayload | null, req: unknown) => void;
  };
}

const defaultConfig: GuardConfig = {
  policy: {
    allowVerified: true,
    allowUnverified: 'challenge',
    blockList: [],
    allowList: [],
  },
  reputation: {
    minScore: 0,
    provider: 'static',
    cacheTtlMs: 300_000,
  },
  rateLimit: {
    windowMs: 60_000,
    maxRequests: 100,
    keyBy: 'agentId',
  },
  jwt: {
    publicKeys: new Map(),
  },
  logging: {},
};

// ──────────────────────────────────────────────────────────────────────────────
// AgentGuard
// ──────────────────────────────────────────────────────────────────────────────

/**
 * AgentGuard — evaluates incoming requests against agent identity,
 * reputation, and rate-limit policies.
 */
export class AgentGuard {
  private readonly config: GuardConfig;
  private readonly policyEngine: PolicyEngine;
  private readonly rateLimiter: RateLimiter;
  private readonly reputationProvider: ReputationProvider;

  /** Cache: agentId → { score, expiresAt } */
  private readonly reputationCache = new Map<
    string,
    { score: ReputationScore; expiresAt: number }
  >();

  /** Resolved CryptoKey map (lazily populated) */
  private resolvedKeys: Map<string, CryptoKey> | null = null;

  constructor(config: Partial<GuardConfig> = {}) {
    this.config = {
      ...defaultConfig,
      ...config,
      policy: { ...defaultConfig.policy, ...config.policy },
      reputation: { ...defaultConfig.reputation, ...config.reputation },
      rateLimit: { ...defaultConfig.rateLimit, ...config.rateLimit },
      jwt: { ...defaultConfig.jwt, ...config.jwt },
      logging: { ...defaultConfig.logging, ...config.logging },
    };

    this.policyEngine = new PolicyEngine();
    this.rateLimiter = new RateLimiter({
      windowMs: this.config.rateLimit.windowMs,
      maxRequests: this.config.rateLimit.maxRequests,
    });
    this.reputationProvider = this.resolveProvider(
      this.config.reputation.provider,
    );
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Core evaluation
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Evaluate a guard request and return the access control decision.
   */
  async evaluate(request: GuardRequest): Promise<GuardResult> {
    // Validate request shape
    const parsed = GuardRequestSchema.safeParse(request);
    if (!parsed.success) {
      return {
        decision: 'deny',
        agent: null,
        reputation: null,
        rateLimit: { remaining: 0, resetMs: 0 },
      };
    }

    const req = parsed.data;

    // 1. Extract and validate JWT
    let agent: AgentIdentityPayload | null = null;
    try {
      const token = this.extractToken(req.headers);
      if (token) {
        const keys = await this.getPublicKeys();
        agent = await validateAgentJWT(token, keys);

        // Check issuer allowlist if configured
        if (
          this.config.jwt.issuerAllowList &&
          this.config.jwt.issuerAllowList.length > 0 &&
          !this.config.jwt.issuerAllowList.includes(agent.iss)
        ) {
          agent = null;
        }
      }
    } catch {
      agent = null;
    }

    // 2. Determine rate-limit key
    const rlKey = this.getRateLimitKey(agent, req);
    const rlResult = await this.rateLimiter.check(rlKey);

    if (!rlResult.allowed) {
      return {
        decision: 'rate-limit',
        agent,
        reputation: null,
        rateLimit: { remaining: 0, resetMs: rlResult.resetMs },
      };
    }

    // 3. Look up reputation (with cache)
    let reputation: ReputationScore | null = null;
    if (agent && this.config.reputation.minScore > 0) {
      reputation = await this.getReputation(agent.agentId);
    }

    // 4. Run policy engine
    const decision = this.policyEngine.evaluate(agent, reputation, {
      allowVerified: this.config.policy.allowVerified,
      allowUnverified: this.config.policy.allowUnverified,
      blockList: this.config.policy.blockList,
      allowList: this.config.policy.allowList,
      minReputationScore: this.config.reputation.minScore,
    });

    // 5. Logging
    if (decision === 'allow' && agent && this.config.logging.onAllow) {
      this.config.logging.onAllow(agent, request);
    } else if (decision === 'deny' && this.config.logging.onDeny) {
      this.config.logging.onDeny('policy deny', request);
    } else if (decision === 'challenge' && this.config.logging.onChallenge) {
      this.config.logging.onChallenge(agent, request);
    }

    return {
      decision,
      agent,
      reputation,
      rateLimit: {
        remaining: rlResult.remaining,
        resetMs: rlResult.resetMs,
      },
    };
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Middleware factories (convenience methods)
  // ──────────────────────────────────────────────────────────────────────────

  /** Returns an Express/Connect middleware function */
  express(): (
    req: ExpressRequest,
    res: ExpressResponse,
    next: () => void,
  ) => Promise<void> {
    return async (req, res, next) => {
      const guardReq: GuardRequest = {
        headers: flattenHeaders(req.headers as Record<string, string | string[] | undefined>),
        ip: req.ip ?? req.socket?.remoteAddress,
        method: req.method ?? 'GET',
        url: req.url ?? '/',
      };

      const result = await this.evaluate(guardReq);
      (req as unknown as Record<string, unknown>)['agent'] = result.agent;

      switch (result.decision) {
        case 'allow':
          next();
          break;
        case 'deny':
          res.status(403).json({ error: 'Forbidden', reason: 'Access denied by policy' });
          break;
        case 'challenge':
          res.status(401).json(this.buildChallengeBody(result.agent));
          break;
        case 'rate-limit':
          res
            .set('Retry-After', String(Math.ceil(result.rateLimit.resetMs / 1000)))
            .status(429)
            .json({ error: 'Too Many Requests', retryAfterMs: result.rateLimit.resetMs });
          break;
      }
    };
  }

  /** Returns a Cloudflare Workers fetch handler */
  worker(): (request: Request) => Promise<Response | null> {
    return async (request: Request): Promise<Response | null> => {
      const headers: Record<string, string> = {};
      request.headers.forEach((value, key) => {
        headers[key.toLowerCase()] = value;
      });

      const guardReq: GuardRequest = {
        headers,
        ip: headers['cf-connecting-ip'] ?? headers['x-forwarded-for'],
        method: request.method,
        url: request.url,
      };

      const result = await this.evaluate(guardReq);

      switch (result.decision) {
        case 'allow':
          return null;
        case 'deny':
          return new Response(
            JSON.stringify({ error: 'Forbidden', reason: 'Access denied by policy' }),
            { status: 403, headers: { 'Content-Type': 'application/json' } },
          );
        case 'challenge':
          return new Response(
            JSON.stringify(this.buildChallengeBody(result.agent)),
            { status: 401, headers: { 'Content-Type': 'application/json' } },
          );
        case 'rate-limit':
          return new Response(
            JSON.stringify({ error: 'Too Many Requests', retryAfterMs: result.rateLimit.resetMs }),
            {
              status: 429,
              headers: {
                'Content-Type': 'application/json',
                'Retry-After': String(Math.ceil(result.rateLimit.resetMs / 1000)),
              },
            },
          );
      }
    };
  }

  /** Returns a Next.js App Router middleware function */
  nextjs(): (request: NextRequest) => Promise<NextResponse> {
    return async (request: NextRequest): Promise<NextResponse> => {
      const headers: Record<string, string> = {};
      request.headers.forEach((value: string, key: string) => {
        headers[key.toLowerCase()] = value;
      });

      const guardReq: GuardRequest = {
        headers,
        ip: headers['x-forwarded-for'] ?? headers['x-real-ip'],
        method: request.method,
        url: request.url,
      };

      const result = await this.evaluate(guardReq);

      switch (result.decision) {
        case 'allow': {
          const response = NextResponse.next();
          if (result.agent) {
            response.headers.set(
              'X-Agent-Id',
              result.agent.agentId,
            );
          }
          return response;
        }
        case 'deny':
          return NextResponse.json(
            { error: 'Forbidden', reason: 'Access denied by policy' },
            { status: 403 },
          );
        case 'challenge':
          return NextResponse.json(
            this.buildChallengeBody(result.agent),
            { status: 401 },
          );
        case 'rate-limit':
          return NextResponse.json(
            { error: 'Too Many Requests', retryAfterMs: result.rateLimit.resetMs },
            {
              status: 429,
              headers: {
                'Retry-After': String(Math.ceil(result.rateLimit.resetMs / 1000)),
              },
            },
          );
      }
    };
  }

  /** Framework-agnostic handler */
  async handle(request: GuardRequest): Promise<GuardResult> {
    return this.evaluate(request);
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Private helpers
  // ──────────────────────────────────────────────────────────────────────────

  private extractToken(headers: Record<string, string>): string | null {
    // Check Authorization: Bearer <token>
    const auth = headers['authorization'] ?? headers['Authorization'];
    if (auth?.startsWith('Bearer ')) {
      return auth.slice(7);
    }
    // Check X-Agent-Identity header
    const identity =
      headers['x-agent-identity'] ?? headers['X-Agent-Identity'];
    if (identity) {
      return identity;
    }
    return null;
  }

  private async getPublicKeys(): Promise<Map<string, CryptoKey>> {
    if (this.resolvedKeys) return this.resolvedKeys;

    let rawKeys: Map<string, string>;
    if (typeof this.config.jwt.publicKeys === 'function') {
      rawKeys = await this.config.jwt.publicKeys();
    } else {
      rawKeys = this.config.jwt.publicKeys;
    }

    const result = new Map<string, CryptoKey>();
    for (const [kid, pem] of rawKeys) {
      const key = await importPublicKeyFromString(pem);
      result.set(kid, key);
    }

    this.resolvedKeys = result;
    return result;
  }

  /** Invalidate the key cache (e.g. on key rotation) */
  invalidateKeyCache(): void {
    this.resolvedKeys = null;
  }

  private getRateLimitKey(
    agent: AgentIdentityPayload | null,
    req: GuardRequest,
  ): string {
    switch (this.config.rateLimit.keyBy) {
      case 'operatorId':
        return agent?.operatorId ?? req.ip ?? 'anonymous';
      case 'ip':
        return req.ip ?? 'unknown';
      case 'agentId':
      default:
        return agent?.agentId ?? req.ip ?? 'anonymous';
    }
  }

  private async getReputation(
    agentId: string,
  ): Promise<ReputationScore | null> {
    const cached = this.reputationCache.get(agentId);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.score;
    }

    const score = await this.reputationProvider.lookup(agentId);
    if (score) {
      this.reputationCache.set(agentId, {
        score,
        expiresAt: Date.now() + this.config.reputation.cacheTtlMs,
      });
    }
    return score;
  }

  private resolveProvider(
    provider: GuardConfig['reputation']['provider'],
  ): ReputationProvider {
    if (typeof provider === 'object') return provider;
    switch (provider) {
      case 'hol':
        return new HOLProvider();
      case 'erc8004':
        return new ERC8004Provider();
      case 'static':
      default:
        return new StaticProvider();
    }
  }

  private buildChallengeBody(agent: AgentIdentityPayload | null): Record<string, unknown> {
    const body: Record<string, unknown> = {
      error: 'Challenge Required',
      challenge: {
        type: this.config.challenge?.type ?? 'pow',
      },
    };
    if (this.config.challenge?.difficulty !== undefined) {
      (body['challenge'] as Record<string, unknown>)['difficulty'] =
        this.config.challenge.difficulty;
    }
    if (agent) {
      body['agentId'] = agent.agentId;
    }
    return body;
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Minimal type shims for framework adapters (no runtime dep on express/next)
// ──────────────────────────────────────────────────────────────────────────────

interface ExpressRequest {
  headers: Record<string, string | string[] | undefined>;
  ip?: string;
  method?: string;
  url?: string;
  socket?: { remoteAddress?: string };
}

interface ExpressResponse {
  status(code: number): ExpressResponse;
  json(body: unknown): void;
  set(header: string, value: string): ExpressResponse;
}

/** Minimal NextRequest shim */
interface NextRequest {
  headers: { forEach(fn: (value: string, key: string) => void): void };
  method: string;
  url: string;
}

/** Minimal NextResponse shim */
interface NextResponse {
  headers: { set(key: string, value: string): void };
}

// In real Next.js this is imported from 'next/server'.
// We declare a compatible shape here so guard compiles without that dep.
const NextResponse = {
  next(): NextResponseWithHeaders {
    return {
      headers: {
        set(_key: string, _value: string) {},
      },
    };
  },
  json(
    body: unknown,
    init?: { status?: number; headers?: Record<string, string> },
  ): NextResponseWithHeaders {
    return {
      body,
      status: init?.status ?? 200,
      headers: {
        set(_key: string, _value: string) {},
        ...init?.headers,
      },
    };
  },
} as const;

interface NextResponseWithHeaders extends NextResponse {
  body?: unknown;
  status?: number;
}

// ──────────────────────────────────────────────────────────────────────────────
// Key import helper
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Import a public key from either:
 * - A base64url-encoded raw 32-byte Ed25519 key
 * - A PEM-encoded SPKI key
 */
async function importPublicKeyFromString(keyStr: string): Promise<CryptoKey> {
  const trimmed = keyStr.trim();

  if (trimmed.startsWith('-----BEGIN PUBLIC KEY-----')) {
    // PEM / SPKI
    const pem = trimmed
      .replace('-----BEGIN PUBLIC KEY-----', '')
      .replace('-----END PUBLIC KEY-----', '')
      .replace(/\s+/g, '');
    const binaryStr = atob(pem);
    const bytes = new Uint8Array(binaryStr.length);
    for (let i = 0; i < binaryStr.length; i++) {
      bytes[i] = binaryStr.charCodeAt(i);
    }
    return crypto.subtle.importKey(
      'spki',
      bytes.buffer,
      { name: 'Ed25519' },
      true,
      ['verify'],
    );
  }

  // Assume raw base64url-encoded 32-byte key
  const padded = trimmed + '='.repeat((4 - (trimmed.length % 4)) % 4);
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');
  const binaryStr = atob(base64);
  const bytes = new Uint8Array(binaryStr.length);
  for (let i = 0; i < binaryStr.length; i++) {
    bytes[i] = binaryStr.charCodeAt(i);
  }
  return crypto.subtle.importKey(
    'raw',
    bytes.buffer,
    { name: 'Ed25519' },
    true,
    ['verify'],
  );
}

// Helpers
function flattenHeaders(
  headers: Record<string, string | string[] | undefined>,
): Record<string, string> {
  const flat: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (typeof value === 'string') {
      flat[key.toLowerCase()] = value;
    } else if (Array.isArray(value)) {
      flat[key.toLowerCase()] = value.join(', ');
    }
  }
  return flat;
}
