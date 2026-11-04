import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { installCursorIntegration, generateCursorConfig, generateCursorScript } from '../src/integrations/cursor.js';
import { processAgentEvent } from '../src/events/gateway.js';
import { StorageEngine } from '../src/storage/store.js';

describe('Cursor Integration & Bridge (src/integrations/cursor.js)', () => {
  test('generateCursorConfig returns valid hooks schema with postToolUseFailure', () => {
    const config = generateCursorConfig();
    assert.equal(config.version, 1);
    assert.ok(Array.isArray(config.hooks.postToolUseFailure));
    assert.equal(config.hooks.postToolUseFailure[0].timeout, 5);
  });

  test('generateCursorScript generates executable node bridge script with 5s watchdog', () => {
    const script = generateCursorScript();
    assert.ok(script.includes('#!/usr/bin/env node'));
    assert.ok(script.includes('event'));
    assert.ok(script.includes('--json'));
    assert.ok(script.includes('--source'));
    assert.ok(script.includes('cursor'));
    assert.ok(script.includes('5000'));
    assert.ok(script.includes('additional_context'));
  });

  test('installCursorIntegration creates .cursor/hooks.json and bridge script in target directory', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-cursor-int-'));
    try {
      const res = installCursorIntegration(tmpDir);
      assert.ok(res.filesCreated.length >= 2);

      const hooksPath = path.join(tmpDir, '.cursor', 'hooks.json');
      const scriptPath = path.join(tmpDir, 'scripts', 'rewind-cursor-hook.js');

      assert.ok(fs.existsSync(hooksPath));
      assert.ok(fs.existsSync(scriptPath));

      const parsedConfig = JSON.parse(fs.readFileSync(hooksPath, 'utf8'));
      assert.equal(parsedConfig.version, 1);
      assert.ok(parsedConfig.hooks.postToolUseFailure);
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('Cursor failure event flows through gateway and yields additional_context', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-cursor-e2e-'));
    let storage = null;
    try {
      storage = new StorageEngine(tmpDir).init();

      // Seed verified incident
      const inc = storage.saveRecord({
        command: 'pytest',
        args: ['tests/test_auth.py'],
        fullCommand: 'pytest tests/test_auth.py',
        cwd: tmpDir,
        durationMs: 120,
        exitCode: 1,
        signal: null,
        success: false,
        stdout: '',
        stderr: 'FAILED tests/test_auth.py::test_login - ConnectionRefusedError: port 6379',
        environment: { platform: process.platform, nodeVersion: process.version },
        git: { isGit: false }
      });

      storage.addRecoveryAttempt(inc.id, {
        cause: 'Redis service not running',
        change: 'docker compose up -d redis',
        verifyCmd: 'redis-cli ping',
        baselineFailed: true
      });
      storage.recordVerificationRun(inc.id, 1, {
        command: 'redis-cli ping',
        exitCode: 0,
        durationMs: 15,
        output: 'PONG'
      });

      // Cursor postToolUseFailure payload
      const cursorPayload = {
        conversation_id: 'conv-cursor-42',
        tool_name: 'Bash',
        tool_input: { command: 'pytest tests/test_auth.py' },
        tool_output: {
          exit_code: 1,
          stderr: 'FAILED tests/test_auth.py::test_login - ConnectionRefusedError: port 6379'
        }
      };

      const result = processAgentEvent(cursorPayload, storage);
      assert.equal(result.action, 'SURFACE');
      assert.ok(result.additional_context);
      assert.ok(result.additional_context.includes('docker compose up -d redis'));
      assert.ok(result.additional_context.includes('redis-cli ping'));
    } finally {
      if (storage) storage.close();
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });
});
