import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
      '@hexhawk/aetherframe-core/browser': path.resolve(__dirname, '../packages/aetherframe-core/src/browser.ts'),
      '@hexhawk/aetherframe-core': path.resolve(__dirname, '../packages/aetherframe-core/src/index.ts'),
    },
  },
  server: {
    port: 5173,
    strictPort: true,
    host: true,
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          const moduleId = id.replace(/\\/g, '/');
          if (moduleId.includes('node_modules')) {
            if (moduleId.includes('reactflow')) return 'react-flow';
            if (moduleId.includes('@tauri-apps')) return 'tauri-runtime';
            if (moduleId.includes('/react/') || moduleId.includes('/react-dom/') || moduleId.includes('scheduler')) return 'react-runtime';
            return 'vendor';
          }
          if (moduleId.includes('/src/utils/nest') || moduleId.includes('/src/components/NestView')) return 'nest-analysis';
          if (moduleId.includes('/src/utils/decompiler') || moduleId.includes('/src/utils/ssa') || moduleId.includes('/src/utils/dataFlow') || moduleId.includes('/src/components/DecompilerView')) return 'decompiler-analysis';
          if (moduleId.includes('/src/utils/correlation') || moduleId.includes('/src/utils/pattern')) return 'verdict-analysis';
          if (moduleId.includes('/src/utils/strike') || moduleId.includes('/src/utils/talon') || moduleId.includes('/src/utils/echo') || moduleId.includes('/src/utils/binaryDiff')) return 'specialist-engines';
          if (moduleId.includes('/src/utils/')) return 'analysis-utilities';
          if (moduleId.includes('/src/components/')) return 'ui-components';
          return undefined;
        },
      },
    },
  },
});