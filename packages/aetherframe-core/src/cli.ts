#!/usr/bin/env node
import { runAetherFrameCli } from './index.js';

const result = runAetherFrameCli(process.argv.slice(2));
if (result.stderr) process.stderr.write(result.stderr);
if (Object.keys(result.stdout).length > 0) {
  process.stdout.write(`${JSON.stringify(result.stdout, null, 2)}\n`);
}
process.exit(result.exitCode);
