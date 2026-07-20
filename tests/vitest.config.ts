import { defineConfig } from 'vitest/config';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  test: {
    include: ['**/*.pbt.test.ts', '**/*.test.ts'],
    environment: 'node',
  },
  resolve: {
    // When running inside core-security/tests after sync:
    //   custody code lives at ../frontend-lib/custody
    // When running from cb1.2/oss-tests:
    //   custody code lives at ../frontend/lib/custody
    alias: {
      '@custody': path.resolve(
        root,
        process.env.OSS_CUSTODY_ROOT ||
          (path.basename(path.resolve(root, '..')) === 'core-security'
            ? '../frontend-lib/custody'
            : '../frontend/lib/custody'),
      ),
    },
  },
});
