# ClawPowers Commerce

> Agent identity, access control, and gate-keeping for the autonomous commerce era.

> **Patent Pending** — Non-Custodial Multi-Chain Financial Infrastructure System for Autonomous AI Agents

[![License: BSL 1.1](https://img.shields.io/badge/License-BSL_1.1-blue.svg)](./LICENSE)

## What is ClawPowers Guard?

ClawPowers Guard is **agent identity middleware** for site operators. It lets you control which AI agents can access your APIs based on their identity, reputation, and behavior — with a single line of middleware.

Agents present an Ed25519-signed JWT via `X-Agent-Identity` or `Authorization: Bearer` header. Guard validates the signature, looks up the agent's reputation score (0-100), and enforces route-level access policies.

## Reputation Tiers

Guard uses a 4-tier reputation system for route-based access control:

| Tier | Min Score | Use Case | Example Routes |
|------|-----------|----------|----------------|
| **Browse** | 0 | Public read access — any agent | `/api/browse/*` |
| **Interact** | 25 | Known agents with basic trust | `/api/interact/*` |
| **Transact** | 50 | Trusted agents that can make purchases | `/api/transact/*` |
| **Premium** | 75 | Premium agents with high reputation | `/api/premium/*` |

- **Unidentified agents** (no JWT) → **401 Challenge** with PoW/captcha protocol
- **Low reputation agents** (below route threshold) → **403 Forbidden**
- **Rate-limited agents** → **429 Too Many Requests** with `Retry-After`

## Quick Start

```bash
npm install @clawpowers/guard @clawpowers/core
```

### Express

```typescript
import { AgentGuard, expressAdapter } from '@clawpowers/guard';

const guard = new AgentGuard({
  routes: {
    '/api/browse/*':   { minReputation: 0 },   // anyone
    '/api/interact/*': { minReputation: 25 },  // known agents
    '/api/transact/*': { minReputation: 50 },  // trusted agents
    '/api/premium/*':  { minReputation: 75 },  // premium agents
  },
  jwt: {
    publicKeys: new Map([['my-key-id', process.env.AGENT_PUBLIC_KEY!]]),
  },
  reputation: {
    minScore: 0,
    provider: 'erc8004', // On-chain ERC-8004 UAID lookup
    cacheTtlMs: 300_000,
  },
  rateLimit: {
    windowMs: 60_000,
    maxRequests: 100,
    keyBy: 'agentId',
  },
});

// Standalone adapter function
app.use(expressAdapter(guard));

// Or use the method directly
app.use(guard.express());
```

### Cloudflare Workers

```typescript
import { AgentGuard, workersAdapter } from '@clawpowers/guard';

const guard = new AgentGuard({
  routes: {
    '/api/browse/*':   { minReputation: 0 },
    '/api/interact/*': { minReputation: 25 },
    '/api/transact/*': { minReputation: 50 },
    '/api/premium/*':  { minReputation: 75 },
  },
  jwt: {
    publicKeys: new Map([['__default__', env.AGENT_PUBLIC_KEY]]),
  },
  reputation: { minScore: 0, provider: 'erc8004', cacheTtlMs: 300_000 },
});

const handler = workersAdapter(guard);

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const blocked = await handler(request);
    if (blocked) return blocked; // 401 / 403 / 429
    return handleRequest(request, env);
  },
};
```

### Next.js App Router

```typescript
// middleware.ts
import { AgentGuard, nextAdapter } from '@clawpowers/guard';

const guard = new AgentGuard({
  routes: {
    '/api/browse/*':   { minReputation: 0 },
    '/api/interact/*': { minReputation: 25 },
    '/api/transact/*': { minReputation: 50 },
    '/api/premium/*':  { minReputation: 75 },
  },
  jwt: {
    publicKeys: new Map([['__default__', process.env.AGENT_PUBLIC_KEY!]]),
  },
});

export const middleware = nextAdapter(guard);

export const config = {
  matcher: '/api/:path*',
};
```

## Packages

| Package | Description |
|---------|-------------|
| [`@clawpowers/core`](./packages/core) | JWT validation, policy engine, rate limiter, reputation providers (zero deps) |
| [`@clawpowers/guard`](./packages/guard) | AgentGuard middleware + Express/Workers/Next.js adapters |

## Architecture

```
@clawpowers/core          (zero runtime dependencies)
  ├── jwt.ts              — EdDSA JWT sign/verify via Web Crypto API
  ├── policy.ts           — Stateless policy engine with glob-based allow/block lists
  ├── rate-limiter.ts     — Sliding window rate limiter (in-memory + KV adapter)
  ├── reputation/         — HOL, ERC-8004, and Static reputation providers
  └── types.ts            — Shared TypeScript interfaces (RoutePolicy, AgentChallenge, etc.)

@clawpowers/guard         (depends on @clawpowers/core + zod)
  └── guard.ts            — AgentGuard: JWT → rate-limit → route-match → reputation → policy
      middleware/
        ├── express.ts    — Express/Connect adapter
        ├── workers.ts    — Cloudflare Workers adapter
        ├── nextjs.ts     — Next.js App Router adapter
        └── generic.ts    — Framework-agnostic adapter
```

## How It Works

1. **Extract JWT** from `X-Agent-Identity` or `Authorization: Bearer` header
2. **Validate signature** using Ed25519 via Web Crypto API (works everywhere)
3. **Rate limit** check per agent/operator/IP (sliding window)
4. **Match route** against configured glob patterns
5. **Look up reputation** score (0-100) from pluggable provider
6. **Enforce threshold**: allow, deny (403), challenge (401), or rate-limit (429)

## Challenge Protocol

When an unidentified agent (no JWT) hits a protected endpoint, Guard returns:

```json
{
  "error": "Challenge Required",
  "challenge": {
    "type": "pow",
    "nonce": "550e8400-e29b-41d4-a716-446655440000",
    "endpoint": "/.well-known/agent-challenge",
    "expiresAt": 1711900800000
  }
}
```

The agent must complete the challenge and re-request with a valid JWT.

## Reputation Providers

| Provider | Description |
|----------|-------------|
| `static` | In-memory scores for testing and manual allowlists |
| `hol` | HOL (History of Links) registry API |
| `erc8004` | On-chain ERC-8004 UAID (Universal Agent Identity) resolver |
| Custom | Any object implementing `ReputationProvider` interface |

## Development

```bash
git clone https://github.com/up2itnow0822/ClawPowers-Commerce.git
cd ClawPowers-Commerce
npm install
npm run build    # Build all packages
npm test         # Run all tests (73 tests across 7 suites)
```

## License

Business Source License 1.1 — see [LICENSE](./LICENSE).
