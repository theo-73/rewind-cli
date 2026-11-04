import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { detectAgentEnvironments, installAllDetected } from '../src/integrations/index.js';
import { installCursorIntegration } from '../src/integrations/cursor.js';
import { StorageEngine } from '../src/storage/store.js';
import { runCLI } from '../src/cli.js';
import { Writable } from 'node:stream';

function createMockIO() {
  let stdoutData = '';
  let stderrData = '';
  const stdout = new Writable({
    write(chunk, enc, cb) { stdoutData += chunk.toString(); cb(); }
  });
  const stderr = new Writable({
    write(chunk, enc, cb) { stderrData += chunk.toString(); cb(); }
  });
  return {
    stdout,
    stderr,
    getStdout: () => stdoutData,
    getStderr: () => stderrData
  };
}

describe('Agent Integrations & Guided Setup (src/integrations/ & src/commands/setup.js)', () => {
  test('detectAgentEnvironments identifies present agent directories', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-detect-'));
    try {
      // Create .cursor/ and .gemini/
      fs.mkdirSync(path.join(tmpDir, '.cursor'), { recursive: true });
      fs.mkdirSync(path.join(tmpDir, '.gemini'), { recursive: true });

      const envs = detectAgentEnvironments(tmpDir);
      assert.equal(envs.cursor, true);
      assert.equal(envs.gemini, true);
      assert.equal(envs.codex, false);
      assert.ok(envs.detected.includes('Cursor'));
      assert.ok(envs.detected.includes('Gemini'));
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('installCursorIntegration writes valid .cursor/hooks.json and bridge script', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-cursor-install-'));
    try {
      const { filesCreated } = installCursorIntegration(tmpDir);
      assert.ok(filesCreated.length >= 2);

      const hooksJsonPath = path.join(tmpDir, '.cursor', 'hooks.json');
      const scriptPath = path.join(tmpDir, 'scripts', 'rewind-cursor-hook.js');

      assert.ok(fs.existsSync(hooksJsonPath));
      assert.ok(fs.existsSync(scriptPath));

      const hooksConfig = JSON.parse(fs.readFileSync(hooksJsonPath, 'utf8'));
      assert.equal(hooksConfig.version, 1);
      assert.ok(Array.isArray(hooksConfig.hooks.postToolUseFailure));
      assert.equal(hooksConfig.hooks.postToolUseFailure[0].command, 'node scripts/rewind-cursor-hook.js');

      const scriptContent = fs.readFileSync(scriptPath, 'utf8');
      assert.ok(scriptContent.includes('event'));
      assert.ok(scriptContent.includes('--json'));
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('rewind setup --dry-run prints plan without creating files', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-setup-dry-'));
    try {
      const io = createMockIO();

      const exitCode = await runCLI([
        '--root', tmpDir,
        'setup',
        '--agent', 'cursor',
        '--dry-run'
      ], {
        ...io,
        isTTY: false
      });

      assert.equal(exitCode, 0);
      assert.ok(io.getStdout().includes('Files that would be created'));
      // Verify no files were actually written
      assert.equal(fs.existsSync(path.join(tmpDir, '.cursor')), false);
      assert.equal(fs.existsSync(path.join(tmpDir, 'scripts')), false);
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('rewind setup --json outputs machine-readable configuration result', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-setup-json-'));
    try {
      const io = createMockIO();

      const exitCode = await runCLI([
        '--root', tmpDir,
        'setup',
        '--agent', 'cursor',
        '--json'
      ], {
        ...io,
        isTTY: false
      });

      assert.equal(exitCode, 0);
      const res = JSON.parse(io.getStdout());
      assert.ok(res);
      assert.equal(res.rootDir, tmpDir);
      assert.ok(Array.isArray(res.installed));
      assert.ok(res.installed.includes('Cursor'));
      assert.ok(res.filesCreated.length >= 2);

      // Verify no CLAUDE.md or .cursorrules clutter was created
      assert.equal(fs.existsSync(path.join(tmpDir, 'CLAUDE.md')), false);
      assert.equal(fs.existsSync(path.join(tmpDir, '.cursorrules')), false);
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('rewind setup --dry-run does not create .rewind directory in workspace', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-setup-clean-'));
    try {
      const io = createMockIO();
      const exitCode = await runCLI([
        '--root', tmpDir,
        'setup',
        '--agent', 'cursor',
        '--dry-run'
      ], {
        ...io,
        isTTY: false
      });

      assert.equal(exitCode, 0);
      assert.equal(fs.existsSync(path.join(tmpDir, '.rewind')), false);
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('rewind setup with --yes runs and configures integrations without prompt', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-setup-yes-'));
    try {
      const io = createMockIO();
      const exitCode = await runCLI([
        '--root', tmpDir,
        'setup',
        '--agent', 'cursor',
        '--yes'
      ], {
        ...io,
        isTTY: true
      });

      assert.equal(exitCode, 0);
      assert.ok(io.getStdout().includes('Setup complete!'));
      assert.ok(fs.existsSync(path.join(tmpDir, '.cursor', 'hooks.json')));
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('rewind setup rejects when no agent is detected and no --agent is specified', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-setup-none-'));
    try {
      const io = createMockIO();
      const exitCode = await runCLI([
        '--root', tmpDir,
        'setup',
        '--yes'
      ], {
        ...io,
        isTTY: false
      });

      assert.notEqual(exitCode, 0);
      assert.ok(io.getStderr().includes('No coding agent detected'));
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('StorageEngine.init() is idempotent when called repeatedly', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-store-idempotent-'));
    let storage = null;
    try {
      storage = new StorageEngine(path.join(tmpDir, '.rewind'));
      storage.init();
      assert.equal(storage.initialized, true);
      assert.ok(storage.db);

      // Call init() a second time on the same instance
      assert.doesNotThrow(() => {
        storage.init();
      });
      assert.equal(storage.initialized, true);
      assert.ok(storage.db);
    } finally {
      if (storage) storage.close();
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });
});
