// Vitest setup for the DOM-mounting ("smoke") suites. Pure-logic suites
// carry `// @vitest-environment node` and never touch the DOM, so this file
// has nothing to do for them — jest-dom matchers and Testing Library's
// cleanup are both no-ops without a document.
import '@testing-library/jest-dom/vitest';
import { cleanup } from '@solidjs/testing-library';
import { afterEach } from 'vitest';

afterEach(() => {
  cleanup();
});
