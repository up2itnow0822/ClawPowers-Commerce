import { defineConfig } from 'vitest/config';
import { resolve } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  test: {
    environment: 'node',
    globals: false,
  },
  resolve: {
    alias: {
      '@clawpowers/core': resolve(__dirname, '../core/src/index.ts'),
    },
  },
});
