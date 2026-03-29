# @clawpowers/core

> Core primitives for agent identity, access control, and reputation. Zero runtime dependencies.

[![License: BSL 1.1](https://img.shields.io/badge/License-BSL_1.1-blue.svg)](../../LICENSE)

## Installation

```bash
npm install @clawpowers/core
```

## Modules

### JWT (`@clawpowers/core/jwt`)

EdDSA (Ed25519) JWT signing and verification using the native Web Crypto API.

```typescript
import {
  validateAgentJWT,
  signAgentJWT,
  generateEd25519KeyPair,
  importEd25519PublicKey,
  JWTValidationError,
} from '@clawpowers/core/jwt';

// Generate a key pair (for testing/issuance)
const keyPair = await generateEd25519KeyPair();

// Sign a token
const token = await signAgentJWT({
  iss: 'https://issuer.example.com',
  sub: 'agent:my-agent',
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  nonce: crypto.randomUUID(),
  operatorId: 'my-operator',
  operatorDomain: 'example.com',
  agentId: 'my-agent-001',
  agentVersion: '1.0.0',
  capabilities: ['browse', 'extract'],
  intent: 'read',
}, keyPair.privateKey);

// Verify a token
const publicKeys = new Map([['__default__', keyPair.publicKey]]);
const payload = await validateAgentJWT(token, publicKeys);
```

### Policy Engine (`@clawpowers/core/policy`)

Stateless policy evaluator with glob-based allow/block lists.

```typescript
import { PolicyEngine, defaultPolicyConfig } from '@clawpowers/core/policy';

const engine = new PolicyEngine();
const decision = engine.evaluate(identity, reputation, {
  ...defaultPolicyConfig,
  blockList: ['evil-operator'],
  minReputationScore: 50,
});
// decision: 'allow' | 'deny' | 'challenge' | 'rate-limit'
```

### Rate Limiter (`@clawpowers/core/rate-limiter`)

Sliding window rate limiter with optional distributed KV adapter.

```typescript
import { RateLimiter } from '@clawpowers/core/rate-limiter';

const limiter = new RateLimiter({ windowMs: 60_000, maxRequests: 100 });
const result = await limiter.check('agent-001');
// result: { allowed: boolean, remaining: number, resetMs: number }
```

### Reputation Providers (`@clawpowers/core/reputation`)

```typescript
import { HOLProvider, ERC8004Provider, StaticProvider } from '@clawpowers/core/reputation';

// Static (testing/manual allowlists)
const provider = new StaticProvider({ 'my-agent': 90 });

// HOL registry
const holProvider = new HOLProvider('https://hol.org/registry/api/v1');
```

## Types

```typescript
import type {
  AgentIdentityPayload,
  AgentCapability,
  AgentIntent,
  PolicyDecision,
  PolicyRule,
  ReputationScore,
  AgentProfile,
} from '@clawpowers/core/types';
```

## License

Business Source License 1.1 — see [LICENSE](../../LICENSE).
