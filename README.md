# ClawPowers Commerce

> Agent identity, access control, and gate-keeping for the autonomous commerce era.

[![License: BSL 1.1](https://img.shields.io/badge/License-BSL_1.1-blue.svg)](./LICENSE)

## Packages

| Package | Version | Description |
|---------|---------|-------------|
| [`@clawpowers/core`](./packages/core) | 1.0.0 | JWT validation, policy engine, rate limiter, reputation providers |
| [`@clawpowers/guard`](./packages/guard) | 1.0.0 | High-level `AgentGuard` class with Express, Workers, and Next.js adapters |

## Architecture

```
@clawpowers/core          (zero runtime dependencies)
  ├── jwt.ts              — EdDSA JWT sign/verify via Web Crypto API
  ├── policy.ts           — Stateless policy engine with glob-based allow/block lists
  ├── rate-limiter.ts     — Sliding window rate limiter (in-memory + KV adapter)
  ├── reputation/         — HOL, ERC-8004, and Static reputation providers
  └── types.ts            — Shared TypeScript interfaces

@clawpowers/guard         (depends on @clawpowers/core + zod)
  └── guard.ts            — AgentGuard: JWT → rate-limit → reputation → policy pipeline
      middleware/
        ├── express.ts    — Express/Connect adapter
        ├── workers.ts    — Cloudflare Workers adapter
        ├── nextjs.ts     — Next.js App Router adapter
        └── generic.ts    — Framework-agnostic adapter
```

## Quick Start

### Install

```bash
npm install @clawpowers/guard @clawpowers/core
```

### Express Middleware

```typescript
import { AgentGuard } from '@clawpowers/guard';

const guard = new AgentGuard({
  jwt: {
    publicKeys: new Map([['my-key-id', process.env.AGENT_PUBLIC_KEY!]]),
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
  logging: {},
});

app.use(guard.express());
```

### Cloudflare Workers

```typescript
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const result = await guard.worker()(request);
    if (result) return result;  // deny / challenge / rate-limit
    return handleRequest(request, env);
  },
};
```

## Development

### Prerequisites

- Node.js 20+
- npm 10+

### Setup

```bash
git clone <repo>
cd ClawPowers-Commerce
npm install
```

### Build

```bash
npm run build          # Build all packages
npm run build -w packages/core   # Build core only
npm run build -w packages/guard  # Build guard only
```

### Test

```bash
npm test               # Run all tests
npm test -w packages/core   # Test core only
npm test -w packages/guard  # Test guard only
```

### Lint

```bash
eslint packages/core/.
eslint packages/guard/.
```

## License

Business Source License 1.1 — see [LICENSE](./LICENSE).
