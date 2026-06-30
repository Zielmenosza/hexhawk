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
});