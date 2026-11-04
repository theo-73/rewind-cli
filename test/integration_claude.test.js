import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { installClaudeIntegration, generateClaudeConfig, generateClaudeScript } from '../src/integrations/claude.js';
import { processAgentEvent, normalizeEvent } from '../src/events/gateway.js';
import { StorageEngine } from '../src/storage/store.js';

describe('Claude Code Integration & Bridge (src/integrations/claude.js)', () => {
  test('generateClaudeConfig returns valid hooks schema with Bash|PowerShell matcher', () => {
    const config = generateClaudeConfig();
    assert.ok(config.hooks);
    assert.ok(Array.isArray(config.hooks.PostToolUseFailure));
    assert.equal(config.hooks.PostToolUseFailure[0].matcher, 'Bash|PowerShell');
    assert.equal(config.hooks.PostToolUseFailure[0].hooks[0].command, 'node scripts/rewind-claude-hook.js');
  });

  test('generateClaudeScript generates executable bridge script with 5s watchdog and native envelope', () => {
    const script = generateClaudeScript();
    assert.ok(script.includes('#!/usr/bin/env node'));
    assert.ok(script.includes('event'));
    assert.ok(script.includes('--json'));
    assert.ok(script.includes('--source'));
    assert.ok(script.includes('claude'));
    assert.ok(script.includes('5000'));
    assert.ok(script.includes('PostToolUseFailure'));
  });

  test('installClaudeIntegration creates .claude/settings.json and scripts/rewind-claude-hook.js', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-claude-int-'));
    try {
      const res = installClaudeIntegration(tmpDir);
      assert.ok(res.filesCreated.length >= 2);

      const settingsPath = path.join(tmpDir, '.claude', 'settings.json');
      const scriptPath = path.join(tmpDir, 'scripts', 'rewind-claude-hook.js');

      assert.ok(fs.existsSync(settingsPath));
      assert.ok(fs.existsSync(scriptPath));

      const parsed = JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
      assert.ok(parsed.hooks.PostToolUseFailure);
      assert.equal(parsed.hooks.PostToolUseFailure[0].matcher, 'Bash|PowerShell');
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('Claude PostToolUseFailure event flows through gateway and yields native envelope', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-claude-failure-'));
    let storage = null;
    try {
      storage = new StorageEngine(tmpDir).init();

      // Seed verified incident
      const inc = storage.saveRecord({
        command: 'pytest',
        args: ['tests/test_api.py'],
        fullCommand: 'pytest tests/test_api.py',
        cwd: tmpDir,
        durationMs: 80,
        exitCode: 1,
        signal: null,
        success: false,
        stdout: '',
        stderr: 'DatabaseConnectionError: could not connect to server at 127.0.0.1:5432',
        environment: { platform: process.platform, nodeVersion: process.version },
        git: { isGit: false }
      });

      storage.addRecoveryAttempt(inc.id, {
        cause: 'PostgreSQL container stopped',
        change: 'docker start postgres-dev',
        verifyCmd: 'pg_isready -h localhost -p 5432',
        baselineFailed: true
      });
      storage.recordVerificationRun(inc.id, 1, {
        command: 'pg_isready -h localhost -p 5432',
        exitCode: 0,
        durationMs: 10,
        output: 'localhost:5432 - accepting connections'
      });

      // Claude Code PostToolUseFailure payload
      const claudePayload = {
        session_id: 'claude-sess-789',
        tool_name: 'Bash',
        tool_input: { command: 'pytest tests/test_api.py' },
        error: 'DatabaseConnectionError: could not connect to server at 127.0.0.1:5432',
        is_interrupt: false
      };

      const result = processAgentEvent(claudePayload, storage, { source: 'claude', cwd: tmpDir });
      assert.ok(result.hookSpecificOutput);
      assert.equal(result.hookSpecificOutput.hookEventName, 'PostToolUseFailure');
      assert.ok(result.hookSpecificOutput.additionalContext.includes('Rewind Verified Fix'));
      assert.ok(result.hookSpecificOutput.additionalContext.includes('docker start postgres-dev'));
    } finally {
      if (storage) storage.close();
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('Claude PreToolUse event evaluates preflight recall and returns advisory envelope', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-claude-preflight-'));
    let storage = null;
    try {
      storage = new StorageEngine(tmpDir).init();

      // Seed verified incident
      const inc = storage.saveRecord({
        command: 'npm',
        args: ['run', 'build'],
        fullCommand: 'npm run build',
        cwd: tmpDir,
        durationMs: 150,
        exitCode: 1,
        signal: null,
        success: false,
        stdout: '',
        stderr: 'Error: Cannot find module esbuild',
        environment: { platform: process.platform, nodeVersion: process.version },
        git: { isGit: false }
      });

      storage.addRecoveryAttempt(inc.id, {
        cause: 'Missing esbuild peer dependency',
        change: 'npm install --save-dev esbuild',
        verifyCmd: 'npm run build',
        baselineFailed: true
      });
      storage.recordVerificationRun(inc.id, 1, {
        command: 'npm run build',
        exitCode: 0,
        durationMs: 100,
        output: 'Build succeeded in 0.5s'
      });

      // Claude PreToolUse payload for the same command
      const preflightPayload = {
        session_id: 'claude-sess-pre-1',
        tool_name: 'Bash',
        tool_input: { command: 'npm run build' },
        hookEventName: 'PreToolUse'
      };

      const result = processAgentEvent(preflightPayload, storage, { source: 'claude', eventType: 'PreToolUse', cwd: tmpDir });
      assert.ok(result.hookSpecificOutput);
      assert.equal(result.hookSpecificOutput.hookEventName, 'PreToolUse');
      assert.ok(result.hookSpecificOutput.additionalContext.includes('Rewind Preflight Advisory'));
      assert.ok(result.hookSpecificOutput.additionalContext.includes('npm install --save-dev esbuild'));

      // Invariant: Non-blocking advisory only — strictly never emit permissionDecision: deny or ask
      assert.equal(result.permissionDecision, undefined);
    } finally {
      if (storage) storage.close();
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('Claude PreToolUse returns empty object {} on silence', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-claude-pre-silence-'));
    let storage = null;
    try {
      storage = new StorageEngine(tmpDir).init();

      const preflightPayload = {
        session_id: 'claude-sess-unknown',
        tool_name: 'Bash',
        tool_input: { command: 'mvn clean install' },
        hookEventName: 'PreToolUse'
      };

      const result = processAgentEvent(preflightPayload, storage, { source: 'claude', eventType: 'PreToolUse', cwd: tmpDir });
      assert.deepEqual(result, {});
    } finally {
      if (storage) storage.close();
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('tool_input discriminator invariant: tool_input alone never infers Cursor', () => {
    const genericPayload = {
      command: 'cargo build',
      exitCode: 1,
      tool_input: { command: 'cargo build' },
      stderr: 'compilation error'
    };

    const event = normalizeEvent(genericPayload);
    assert.notEqual(event.source, 'cursor');
    assert.equal(event.source, 'generic');
  });
});
