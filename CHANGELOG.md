# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-03-29

### Added

#### @clawpowers/core
- `validateAgentJWT` — EdDSA JWT validation using native Web Crypto API (zero dependencies)
- `signAgentJWT` — JWT signing for issuance and testing
- `generateEd25519KeyPair` / `importEd25519PublicKey` — key management utilities
- `JWTValidationError` — typed error class with `code` field for programmatic handling
- `PolicyEngine` — stateless policy evaluator with glob-based allow/block lists
- `RateLimiter` — sliding window rate limiter with in-memory + optional KV adapter
- `HOLProvider` — History of Links registry reputation provider
- `ERC8004Provider` — ERC-8004 UAID resolver stub
- `StaticProvider` — static reputation provider for testing and manual allowlists
- Full TypeScript strict-mode typings for all exported APIs

#### @clawpowers/guard
- `AgentGuard` — unified agent access control class (JWT → rate-limit → reputation → policy)
- `guard.express()` — Express/Connect middleware factory
- `guard.worker()` — Cloudflare Workers handler factory
- `guard.nextjs()` — Next.js App Router middleware factory
- `guard.handle()` — framework-agnostic evaluation
- Zod schema validation for incoming `GuardRequest` objects
- Configurable logging callbacks (`onAllow`, `onDeny`, `onChallenge`)
- Reputation caching with configurable TTL
- Lazy key import with cache invalidation via `invalidateKeyCache()`
