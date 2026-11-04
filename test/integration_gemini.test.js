import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { installGeminiIntegration, generateGeminiConfig, generateGeminiScript } from '../src/integrations/gemini.js';
import { processAgentEvent } from '../src/events/gateway.js';
import { StorageEngine } from '../src/storage/store.js';

describe('Gemini CLI Integration & Bridge (src/integrations/gemini.js)', () => {
  test('generateGeminiConfig returns valid nested hooks schema with run_shell_command matcher', () => {
    const config = generateGeminiConfig();
    assert.ok(config.hooks);
    assert.ok(Array.isArray(config.hooks.AfterTool));
    assert.equal(config.hooks.AfterTool[0].matcher, 'run_shell_command');
    assert.ok(Array.isArray(config.hooks.AfterTool[0].hooks));
    assert.equal(config.hooks.AfterTool[0].hooks[0].type, 'command');
    assert.ok(config.hooks.AfterTool[0].hooks[0].command.includes('rewind-gemini-hook.js'));
  });

  test('generateGeminiScript generates executable bridge script with native envelope and 5s watchdog', () => {
    const script = generateGeminiScript();
    assert.ok(script.includes('#!/usr/bin/env node'));
    assert.ok(script.includes('event'));
    assert.ok(script.includes('--json'));
    assert.ok(script.includes('--source'));
    assert.ok(script.includes('gemini'));
    assert.ok(script.includes('5000'));
    assert.ok(script.includes('hookSpecificOutput'));
    assert.ok(script.includes('AfterTool'));
  });

  test('installGeminiIntegration creates .gemini/settings.json and scripts/rewind-gemini-hook.js', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-gemini-int-'));
    try {
      const res = installGeminiIntegration(tmpDir);
      assert.ok(res.filesCreated.length >= 2);

      const settingsPath = path.join(tmpDir, '.gemini', 'settings.json');
      const scriptPath = path.join(tmpDir, 'scripts', 'rewind-gemini-hook.js');

      assert.ok(fs.existsSync(settingsPath));
      assert.ok(fs.existsSync(scriptPath));

      const parsedConfig = JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
      assert.ok(parsedConfig.hooks?.AfterTool);
      assert.equal(parsedConfig.hooks.AfterTool[0].matcher, 'run_shell_command');
      assert.equal(parsedConfig.hooks.AfterTool[0].hooks[0].name, 'rewind-gemini-hook');
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('Gemini failure event flows through gateway and yields hookSpecificOutput', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-gemini-e2e-'));
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
        stderr: 'AssertionError: auth token invalid',
        environment: { platform: process.platform, nodeVersion: process.version },
        git: { isGit: false }
      });

      storage.addRecoveryAttempt(inc.id, {
        cause: 'Expired mock JWT secret in test fixture',
        change: 'Updated JWT_SECRET to valid constant in conftest.py',
        verifyCmd: 'pytest tests/test_auth.py',
        baselineFailed: true
      });

      storage.recordVerificationRun(inc.id, 1, {
        command: 'pytest tests/test_auth.py',
        exitCode: 0,
        durationMs: 45,
        output: '1 passed in 0.05s'
      });

      // Simulate Gemini hook payload
      const geminiPayload = {
        session_id: 'gemini-sess-456',
        tool_name: 'run_shell_command',
        parameters: {
          command: 'pytest tests/test_auth.py',
          cwd: tmpDir
        },
        result: {
          exit_code: 1,
          stderr: 'AssertionError: auth token invalid',
          stdout: ''
        }
      };

      const result = processAgentEvent(geminiPayload, storage, { cwd: tmpDir });
      assert.equal(result.action, 'SURFACE');
      assert.ok(result.hookSpecificOutput);
      assert.ok(result.hookSpecificOutput.additionalContext.includes('Rewind Verified Fix'));
      assert.ok(result.hookSpecificOutput.additionalContext.includes('Updated JWT_SECRET'));
    } finally {
      if (storage) storage.close();
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });
});
