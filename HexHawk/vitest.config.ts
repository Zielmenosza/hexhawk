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
    },
  },
  test: {
    globals: true,
    // Use jsdom for React component and hook tests; node for pure engine tests
    environmentMatchGlobs: [
      ['src/components/**/*.test.tsx', 'jsdom'],
      ['src/components/__tests__/**/*.test.tsx', 'jsdom'],
      ['src/utils/__tests__/useVirtualList.test.ts', 'jsdom'],
      ['src/utils/__tests__/corpusManager.test.ts', 'jsdom'],
      ['src/utils/__tests__/benchmarkHarness.test.ts', 'jsdom'],
    ],
    environment: 'node',
    setupFiles: ['src/test/setup.ts'],
    include: [
      'src/**/__tests__/**/*.{test,spec}.{ts,tsx}',
      'src/**/*.{test,spec}.{ts,tsx}',
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
