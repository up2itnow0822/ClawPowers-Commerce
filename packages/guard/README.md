# @clawpowers/guard

> Agent identity middleware with route-based reputation tiers for Express, Cloudflare Workers, and Next.js.

[![License: BSL 1.1](https://img.shields.io/badge/License-BSL_1.1-blue.svg)](../../LICENSE)

## Installation

```bash
npm install @clawpowers/guard @clawpowers/core
```

## Usage

### Route-Based Reputation Tiers

The core feature: configure different reputation thresholds per route pattern.

```typescript
import { AgentGuard } from '@clawpowers/guard';

const guard = new AgentGuard({
  routes: {
    '/api/browse/*':   { minReputation: 0 },   // anyone with valid JWT
    '/api/interact/*': { minReputation: 25 },  // known agents
    '/api/transact/*': { minReputation: 50 },  // trusted agents
    '/api/premium/*':  { minReputation: 75 },  // premium agents
  },
  jwt: {
    publicKeys: new Map([['my-key', process.env.AGENT_PUBLIC_KEY!]]),
  },
  reputation: {
    minScore: 0,
    provider: 'erc8004',
    cacheTtlMs: 300_000,
  },
});
```

### Express / Connect

```typescript
import { AgentGuard, expressAdapter } from '@clawpowers/guard';

// Standalone adapter function
app.use(expressAdapter(guard));

// Or use the method
app.use(guard.express());

// Access agent identity in route handlers
app.get('/api/browse/products', (req, res) => {
  const agent = req.agent; // AgentIdentityPayload | null
  res.json({ products: [...] });
});
```

### Cloudflare Workers

```typescript
import { AgentGuard, workersAdapter } from '@clawpowers/guard';

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

const guard = new AgentGuard({ /* config */ });
export const middleware = nextAdapter(guard);

export const config = {
  matcher: '/api/:path*',
};
```

### Framework-Agnostic

```typescript
const result = await guard.handle({
  headers: { authorization: `Bearer ${token}` },
  method: 'GET',
  url: '/api/premium/analytics',
});

switch (result.decision) {
  case 'allow':      /* proceed */                    break;
  case 'deny':       /* 403 — low reputation */       break;
  case 'challenge':  /* 401 — unidentified agent */   break;
  case 'rate-limit': /* 429 — too many requests */    break;
}
```

## Decision Flow

```
Request → Extract JWT → Rate Limit Check → Match Route → Lookup Reputation → Decision
                │                                │                    │
                ├─ No JWT ──────────────────────────────────────→ 401 Challenge
                ├─ Rate limited ────────────────────────────────→ 429 Retry-After
                ├─ Blocked operator ────────────────────────────→ 403 Forbidden
                └─ Reputation < route threshold ────────────────→ 403 Forbidden
                                                                  │
                                                              200 Allow ✓
```

## Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `routes` | `Record<string, RoutePolicy>` | `undefined` | Route-level reputation thresholds (glob patterns) |
| `jwt.publicKeys` | `Map<string, string>` or async fn | `new Map()` | Ed25519 public keys (base64url raw or PEM SPKI) |
| `jwt.issuerAllowList` | `string[]` | `undefined` | Restrict to specific issuers |
| `policy.allowVerified` | `boolean` | `true` | Allow agents with valid JWTs |
| `policy.allowUnverified` | `'challenge' \| 'deny'` | `'challenge'` | Behaviour for unidentified agents |
| `policy.blockList` | `string[]` | `[]` | Glob patterns for operatorIds to block |
| `policy.allowList` | `string[]` | `[]` | Glob patterns that bypass all checks |
| `rateLimit.windowMs` | `number` | `60000` | Sliding window in milliseconds |
| `rateLimit.maxRequests` | `number` | `100` | Max requests per window |
| `rateLimit.keyBy` | `'agentId' \| 'operatorId' \| 'ip'` | `'agentId'` | Rate limit key strategy |
| `reputation.minScore` | `number` | `0` | Global minimum score (fallback for unmatched routes) |
| `reputation.provider` | `'hol' \| 'erc8004' \| 'static' \| ReputationProvider` | `'static'` | Reputation provider |
| `reputation.cacheTtlMs` | `number` | `300000` | Reputation cache TTL |
| `challenge.type` | `'pow' \| 'captcha' \| 'redirect'` | `'pow'` | Challenge type for unidentified agents |

## Adapter Functions

Three standalone adapter functions are provided for convenience:

```typescript
import { expressAdapter, workersAdapter, nextAdapter } from '@clawpowers/guard';

// Express
app.use(expressAdapter(guard));

// Workers
const handler = workersAdapter(guard);

// Next.js
export const middleware = nextAdapter(guard);
```

## License

Business Source License 1.1 — see [LICENSE](../../LICENSE).
