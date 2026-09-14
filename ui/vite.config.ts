/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import solid from 'vite-plugin-solid';

export default defineConfig({
  plugins: [solid()],
  server: {
    proxy: {
      '/api': { target: 'http://localhost:8080', changeOrigin: true },
    },
  },
  // Vitest runs under Node's module resolution, which would otherwise pick
  // solid-js's `node` export condition — a server-rendering build whose
  // signals/effects don't behave like the real, reactive browser build the
  // app actually ships. Scoped to `process.env.VITEST` (set by vitest
  // itself) so it never touches the real dev/build resolution.
  resolve: process.env.VITEST ? { conditions: ['browser'] } : undefined,
  test: {
    // Pure-logic suites opt back into `node` via a leading
    // `// @vitest-environment node` comment — this default only affects
    // suites (like the view smoke tests) that actually touch the DOM.
    environment: 'jsdom',
    setupFiles: ['./src/testSetup.ts'],
  },
});
