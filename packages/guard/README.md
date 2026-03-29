# @clawpowers/guard

> High-level agent access control guard with framework adapters for Express, Cloudflare Workers, and Next.js.

[![License: BSL 1.1](https://img.shields.io/badge/License-BSL_1.1-blue.svg)](../../LICENSE)

## Installation

```bash
npm install @clawpowers/guard
```

## Usage

### Express / Connect

```typescript
import { AgentGuard } from '@clawpowers/guard';

const guard = new AgentGuard({
  jwt: {
    publicKeys: new Map([['my-key', process.env.AGENT_PUBLIC_KEY!]]),
  },
  policy: {
    allowVerified: true,
    allowUnverified: 'challenge',
    blockList: [],
    allowList: [],
  },
  rateLimit: {
    windowMs: 60_000,
    maxRequests: 100,
    keyBy: 'agentId',
  },
  reputation: {
    minScore: 0,
    provider: 'static',
    cacheTtlMs: 300_000,
  },
  logging: {
    onAllow: (agent, req) => console.log(`Allowed: ${agent.agentId}`),
    onDeny: (reason, req) => console.log(`Denied: ${reason}`),
  },
});

// Express middleware
app.use('/api', guard.express());
```

### Cloudflare Workers

```typescript
const worker = guard.worker();

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const blocked = await worker(request);
    if (blocked) return blocked;
    return handleRequest(request, env);
  },
};
```

### Next.js App Router

```typescript
// middleware.ts
import { AgentGuard } from '@clawpowers/guard';

const guard = new AgentGuard({ /* config */ });
const nextMiddleware = guard.nextjs();

export async function middleware(request: NextRequest) {
  return nextMiddleware(request);
}
```

### Framework-agnostic

```typescript
const result = await guard.handle({
  headers: { authorization: `Bearer ${token}` },
  method: 'GET',
  url: '/api/resource',
});

switch (result.decision) {
  case 'allow': /* proceed */ break;
  case 'deny': /* 403 */ break;
  case 'challenge': /* 401 + challenge */ break;
  case 'rate-limit': /* 429 */ break;
}
```

## Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `jwt.publicKeys` | `Map<string, string>` or `() => Promise<Map<string, string>>` | `new Map()` | Ed25519 public keys (base64url raw or PEM SPKI) |
| `jwt.issuerAllowList` | `string[]` | `undefined` | Restrict to specific issuers |
| `policy.allowVerified` | `boolean` | `true` | Allow agents with valid JWTs |
| `policy.allowUnverified` | `'challenge' \| 'deny'` | `'challenge'` | Behaviour for requests without valid JWT |
| `policy.blockList` | `string[]` | `[]` | Glob patterns for operatorIds to block |
| `policy.allowList` | `string[]` | `[]` | Glob patterns that bypass all other checks |
| `rateLimit.windowMs` | `number` | `60000` | Rate limit window in milliseconds |
| `rateLimit.maxRequests` | `number` | `100` | Max requests per window |
| `rateLimit.keyBy` | `'agentId' \| 'operatorId' \| 'ip'` | `'agentId'` | Rate limit key strategy |
| `reputation.minScore` | `number` | `0` | Minimum reputation score (0 = disabled) |
| `reputation.provider` | `'hol' \| 'erc8004' \| 'static' \| ReputationProvider` | `'static'` | Reputation provider |
| `reputation.cacheTtlMs` | `number` | `300000` | Reputation cache TTL |

## License

Business Source License 1.1 — see [LICENSE](../../LICENSE).
