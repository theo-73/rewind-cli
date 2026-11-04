import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { normalizeEvent, processAgentEvent } from '../src/events/gateway.js';
import { StorageEngine } from '../src/storage/store.js';
import { runCLI } from '../src/cli.js';
import { PassThrough, Writable } from 'node:stream';

function createMockIO() {
  let stdoutData = '';
  let stderrData = '';
  const stdout = new Writable({
    write(chunk, enc, cb) { stdoutData += chunk.toString(); cb(); }
  });
  const stderr = new Writable({
    write(chunk, enc, cb) { stderrData += chunk.toString(); cb(); }
  });
  const stdin = new PassThrough();
  return {
    stdin,
    stdout,
    stderr,
    getStdout: () => stdoutData,
    getStderr: () => stderrData
  };
}

describe('Agent Event Gateway (src/events/gateway.js & src/commands/event.js)', () => {
  test('normalizeEvent normalizes Cursor postToolUseFailure payloads', () => {
    const cursorPayload = {
      conversation_id: 'conv-abc',
      tool_name: 'Bash',
      tool_input: { command: 'npm test -- --grep "auth"' },
      tool_output: { exit_code: 1, stderr: 'AssertionError: expected 200 to equal 401' }
    };

    const event = normalizeEvent(cursorPayload);
    assert.equal(event.source, 'cursor');
    assert.equal(event.sessionId, 'conv-abc');
    assert.equal(event.command, 'npm');
    assert.deepEqual(event.args, ['test', '--', '--grep', 'auth']);
    assert.equal(event.exitCode, 1);
    assert.ok(event.stderr.includes('AssertionError'));
  });

  test('normalizeEvent normalizes Gemini CLI AfterTool payloads', () => {
    const geminiPayload = {
      session_id: 'sess-xyz',
      tool_name: 'run_command',
      parameters: { command: 'pytest tests/test_api.py' },
      result: { exit_code: 1, error: 'ConnectionRefusedError: port 5432' }
    };

    const event = normalizeEvent(geminiPayload);
    assert.equal(event.source, 'gemini');
    assert.equal(event.sessionId, 'sess-xyz');
    assert.equal(event.command, 'pytest');
    assert.equal(event.exitCode, 1);
    assert.ok(event.stderr.includes('ConnectionRefusedError'));
  });

  test('normalizeEvent normalizes Codex PostToolUse payloads', () => {
    const codexPayload = {
      tool: 'bash',
      input: { command: 'cargo build' },
      output: { exitCode: 101, stderr: 'error[E0425]: cannot find value' }
    };

    const event = normalizeEvent(codexPayload);
    assert.equal(event.source, 'codex');
    assert.equal(event.command, 'cargo');
    assert.equal(event.exitCode, 101);
  });

  test('processAgentEvent discards cancellation and returns silent context', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-gtw-cancel-'));
    let storage = null;
    try {
      storage = new StorageEngine(tmpDir).init();

      const res = processAgentEvent({
        command: 'npm start',
        exitCode: 130
      }, storage);

      assert.equal(res.action, 'SILENCE');
      assert.equal(res.classification, 'DISCARD');
      assert.equal(res.additionalContext, null);
      assert.equal(res.additional_context, null);
    } finally {
      if (storage) storage.close();
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('processAgentEvent surfaces verified fix and dead-end warnings for recurring failure', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-gtw-surface-'));
    let storage = null;
    try {
      storage = new StorageEngine(tmpDir).init();

      // Seed historical verified incident
      const inc = storage.saveRecord({
        command: 'npm',
        args: ['test'],
        fullCommand: 'npm test',
        cwd: tmpDir,
        durationMs: 50,
        exitCode: 1,
        signal: null,
        success: false,
        stdout: '',
        stderr: 'FATAL: database port unreachable',
        environment: { platform: process.platform, nodeVersion: process.version },
        git: { isGit: false }
      });

      storage.addRecoveryAttempt(inc.id, {
        cause: 'Wrong database port in .env',
        change: 'Changed port to 5432 in .env.local',
        verifyCmd: 'node -e "process.exit(0);"',
        baselineFailed: true
      });
      storage.recordVerificationRun(inc.id, 1, {
        command: 'node -e "process.exit(0);"',
        exitCode: 0,
        durationMs: 20,
        output: 'Connected'
      });

      // Add a failed attempt to test negative memory warning
      storage.addRecoveryAttempt(inc.id, {
        cause: 'Tried deleting node_modules',
        change: 'rm -rf node_modules',
        verifyCmd: 'node -e "process.exit(1);"'
      });
      storage.recordVerificationRun(inc.id, 2, {
        command: 'node -e "process.exit(1);"',
        exitCode: 1,
        durationMs: 20,
        output: 'Still failed'
      });

      // Now incoming Cursor event for the same failure
      const cursorPayload = {
        conversation_id: 'conv-101',
        tool_name: 'Bash',
        tool_input: { command: 'npm test' },
        tool_output: { exit_code: 1, stderr: 'FATAL: database port unreachable' }
      };

      const res = processAgentEvent(cursorPayload, storage);
      assert.equal(res.action, 'SURFACE');
      assert.equal(res.classification, 'PROMOTE');
      assert.ok(res.additionalContext);
      assert.ok(res.additionalContext.includes('Changed port to 5432 in .env.local'));
      assert.ok(res.additionalContext.includes('Avoid: "rm -rf node_modules"'));
      assert.equal(res.additional_context, res.additionalContext);
    } finally {
      if (storage) storage.close();
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('rewind event --json CLI command processes input from flag and outputs JSON', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-gtw-cli-'));
    let storage = null;
    try {
      storage = new StorageEngine(tmpDir).init();
      const io = createMockIO();

      const payload = JSON.stringify({
        command: 'pytest',
        exitCode: 1,
        stderr: 'AssertionError: test failed'
      });

      const exitCode = await runCLI([
        '--root', tmpDir,
        'event',
        '--json',
        '--data', payload
      ], {
        ...io,
        isTTY: false
      });

      assert.equal(exitCode, 0);
      const outText = io.getStdout();
      const parsed = JSON.parse(outText);
      assert.ok(parsed);
      assert.equal(parsed.classification, 'PROMOTE');
    } finally {
      if (storage) storage.close();
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });
});
