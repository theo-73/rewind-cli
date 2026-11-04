import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { installCodexIntegration, generateCodexConfig, generateCodexScript } from '../src/integrations/codex.js';
import { processAgentEvent } from '../src/events/gateway.js';
import { StorageEngine } from '../src/storage/store.js';

describe('Codex Integration & Bridge (src/integrations/codex.js)', () => {
  test('generateCodexConfig returns valid nested hooks schema without duplicate sibling PostToolUse', () => {
    const config = generateCodexConfig();
    assert.equal(config.PostToolUse, undefined, 'Duplicate top-level sibling PostToolUse must not exist');
    assert.ok(config.hooks?.PostToolUse, 'Nested hooks.PostToolUse must exist');
    const postTool = config.hooks.PostToolUse;
    assert.ok(Array.isArray(postTool));
    assert.equal(postTool[0].matcher, 'Bash');
    assert.ok(Array.isArray(postTool[0].hooks));
    assert.equal(postTool[0].hooks[0].type, 'command');
    assert.ok(postTool[0].hooks[0].command.includes('rewind-codex-hook.js'));
  });

  test('generateCodexScript generates executable bridge script with native envelope', () => {
    const script = generateCodexScript();
    assert.ok(script.includes('#!/usr/bin/env node'));
    assert.ok(script.includes('event'));
    assert.ok(script.includes('--json'));
    assert.ok(script.includes('--source'));
    assert.ok(script.includes('codex'));
    assert.ok(script.includes('5000'));
    assert.ok(script.includes('hookSpecificOutput'));
    assert.ok(script.includes('PostToolUse'));
  });

  test('installCodexIntegration creates .codex/hooks.json and scripts/rewind-codex-hook.js', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-codex-int-'));
    try {
      const res = installCodexIntegration(tmpDir);
      assert.ok(res.filesCreated.length >= 2);

      const hooksPath = path.join(tmpDir, '.codex', 'hooks.json');
      const scriptPath = path.join(tmpDir, 'scripts', 'rewind-codex-hook.js');

      assert.ok(fs.existsSync(hooksPath));
      assert.ok(fs.existsSync(scriptPath));

      const parsedConfig = JSON.parse(fs.readFileSync(hooksPath, 'utf8'));
      assert.equal(parsedConfig.PostToolUse, undefined, 'No duplicate top-level PostToolUse allowed');
      assert.ok(parsedConfig.hooks?.PostToolUse);
      const postTool = parsedConfig.hooks.PostToolUse;
      assert.equal(postTool[0].matcher, 'Bash');
      assert.equal(postTool[0].hooks[0].name, 'rewind-codex-hook');
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('Codex failure event flows through gateway and yields hookSpecificOutput', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-codex-e2e-'));
    let storage = null;
    try {
      storage = new StorageEngine(tmpDir).init();

      // Seed verified incident
      const inc = storage.saveRecord({
        command: 'cargo',
        args: ['test'],
        fullCommand: 'cargo test',
        cwd: tmpDir,
        durationMs: 300,
        exitCode: 101,
        signal: null,
        success: false,
        stdout: '',
        stderr: 'error[E0425]: cannot find value `config` in this scope',
        environment: { platform: process.platform, nodeVersion: process.version },
        git: { isGit: false }
      });

      storage.addRecoveryAttempt(inc.id, {
        cause: 'Missing use crate::config import',
        change: 'Added use crate::config; at top of main.rs',
        verifyCmd: 'cargo test',
        baselineFailed: true
      });

      storage.recordVerificationRun(inc.id, 1, {
        command: 'cargo test',
        exitCode: 0,
        durationMs: 90,
        output: 'test result: ok. 4 passed; 0 failed'
      });

      // Simulate Codex hook payload
      const codexPayload = {
        tool: 'Bash',
        input: {
          command: 'cargo test',
          cwd: tmpDir
        },
        output: {
          exitCode: 101,
          stderr: 'error[E0425]: cannot find value `config` in this scope',
          stdout: ''
        }
      };

      const result = processAgentEvent(codexPayload, storage, { cwd: tmpDir });
      assert.equal(result.action, 'SURFACE');
      assert.ok(result.hookSpecificOutput);
      assert.ok(result.hookSpecificOutput.additionalContext.includes('Rewind Verified Fix'));
      assert.ok(result.hookSpecificOutput.additionalContext.includes('Added use crate::config'));
    } finally {
      if (storage) storage.close();
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });
});
