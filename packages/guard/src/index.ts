// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ClawPowers Commerce. All Rights Reserved.
// See LICENSE in the repository root for license information.

export {
  AgentGuard,
  expressAdapter,
  workersAdapter,
  nextAdapter,
} from './guard.js';
export type { GuardConfig, GuardRequest, GuardResult } from './guard.js';

// Middleware adapters (re-exports for backward compat)
export * from './middleware/express.js';
export * from './middleware/workers.js';
export * from './middleware/nextjs.js';
export * from './middleware/generic.js';
