#!/usr/bin/env npx tsx
/**
 * CLI entry point for: npx tsx src/eval/run-eval.ts
 * or: npm run eval
 */

import { runEvalCLI } from './eval-harness.js';

runEvalCLI().catch((err) => {
  console.error('Eval failed:', err);
  process.exitCode = 1;
});
