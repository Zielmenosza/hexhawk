import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      // Stub Tauri runtime APIs — not available in test environment
      '@tauri-apps/api/core': resolve(__dirname, 'src/test/__mocks__/tauri-core.ts'),
      '@tauri-apps/plugin-dialog': resolve(__dirname, 'src/test/__mocks__/tauri-dialog.ts'),
      '@hexhawk/aetherframe-core/browser': resolve(__dirname, '../packages/aetherframe-core/src/browser.ts'),
      '@hexhawk/aetherframe-core': resolve(__dirname, '../packages/aetherframe-core/src/index.ts'),
    },
  },
  test: {
    // Vitest 4 removed environmentMatchGlobs. Keep DOM-dependent tests in a
    // jsdom project and pure engine tests in the Node project.
    projects: [
      {
        extends: true,
        test: {
          name: 'node',
          globals: true,
          environment: 'node',
          setupFiles: ['src/test/setup.ts'],
          include: [
            'src/**/__tests__/**/*.{test,spec}.{ts,tsx}',
            'src/**/*.{test,spec}.{ts,tsx}',
          ],
          exclude: [
            'src/components/**/*.test.tsx',
            'src/utils/__tests__/useVirtualList.test.ts',
            'src/utils/__tests__/corpusManager.test.ts',
            'src/utils/__tests__/benchmarkHarness.test.ts',
          ],
        },
      },
      {
        extends: true,
        test: {
          name: 'jsdom',
          globals: true,
          environment: 'jsdom',
          setupFiles: ['src/test/setup.ts'],
          include: [
            'src/components/**/*.test.tsx',
            'src/utils/__tests__/useVirtualList.test.ts',
            'src/utils/__tests__/corpusManager.test.ts',
            'src/utils/__tests__/benchmarkHarness.test.ts',
          ],
        },
      },
    ],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov'],
      include: [
        'src/utils/**/*.ts',
        'src/components/**/*.tsx',
      ],
      exclude: [
        'src/test/**',
        'src/**/__tests__/**',
        '**/*.d.ts',
        'src/main.tsx',
        'src/App.tsx',
      ],
      thresholds: {
        // Critical engine paths — enforced on every CI run
        'src/utils/correlationEngine.ts': { lines: 90, functions: 90, branches: 85 },
        'src/utils/nestEngine.ts':        { lines: 85, functions: 85, branches: 80 },
        'src/utils/talonEngine.ts':       { lines: 85, functions: 85, branches: 80 },
        'src/utils/ssaTransform.ts':      { lines: 90, functions: 90, branches: 85 },
        'src/utils/dataFlowPasses.ts':    { lines: 90, functions: 90, branches: 85 },
        'src/utils/signatureEngine.ts':   { lines: 85, functions: 85, branches: 80 },
        'src/utils/operatorConsole.ts':   { lines: 85, functions: 85, branches: 80 },
        // Global floor
        lines: 70,
        functions: 70,
        branches: 65,
      },
    },
  },
});
