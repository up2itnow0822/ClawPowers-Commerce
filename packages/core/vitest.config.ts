// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ClawPowers Commerce. All Rights Reserved.
// See LICENSE in the repository root for license information.

import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    globals: false,
  },
});
