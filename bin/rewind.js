#!/usr/bin/env node

// Startup Node.js engine version guard
const [major, minor] = process.versions.node.split('.').map(Number);
if (major < 22 || (major === 22 && minor < 13)) {
  console.error(`rewind: Node.js >= 22.13.0 is required (running on ${process.version}). Please upgrade Node.js.`);
  process.exit(1);
}

import { runCLI } from '../src/cli.js';

// Suppress SQLite ExperimentalWarning
const originalEmit = process.emit;
process.emit = function (name, data, ...args) {
  if (name === 'warning' && data?.name === 'ExperimentalWarning' && typeof data?.message === 'string' && data.message.includes('SQLite')) {
    return false;
  }
  return originalEmit.apply(process, [name, data, ...args]);
};

process.stdout.on('error', (err) => {
  if (err.code === 'EPIPE') {
    process.exit(0);
  }
});

const exitCode = await runCLI(process.argv.slice(2));
process.exitCode = exitCode;
