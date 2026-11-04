import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { StorageEngine } from '../src/storage/store.js';
import { evaluateSurfacing } from '../src/storage/surfacing.js';

describe('Surfacing Engine & Abstention Policy (src/storage/surfacing.js)', () => {
  test('returns SILENCE when no historical failures match fingerprint', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-surf-silence-'));
    let storage = null;
    try {
      storage = new StorageEngine(tmpDir).init();

      const decision = evaluateSurfacing({
        command: 'cargo',
        args: ['test'],
        exitCode: 1,
        stderr: 'compilation error'
      }, storage);

      assert.equal(decision.action, 'SILENCE');
      assert.equal(decision.matchType, 'NONE');
      assert.equal(decision.bestCandidate, null);
      assert.equal(decision.relevantFailedApproaches.length, 0);
    } finally {
      if (storage) storage.close();
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('returns SURFACE for exact match with verified recovery and compatible environment', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-surf-surface-'));
    let storage = null;
    try {
      storage = new StorageEngine(tmpDir).init();

      // 1. Historical failure that was verified
      const inc1 = storage.saveRecord({
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
        environment: { platform: 'win32', nodeVersion: 'v22.0.0', nodeMajor: 22 },
        git: { isGit: false }
      });

      storage.addRecoveryAttempt(inc1.id, {
        cause: 'Postgres not running',
        change: 'Started local postgres service',
        verifyCmd: 'node -e "process.exit(0);"',
        baselineFailed: true
      });

      storage.recordVerificationRun(inc1.id, 1, {
        command: 'node -e "process.exit(0);"',
        exitCode: 0,
        durationMs: 30,
        output: 'Success'
      });

      // 2. Current failure in the SAME environment
      const currentFailure = {
        command: 'npm',
        args: ['test'],
        fullCommand: 'npm test',
        cwd: tmpDir,
        durationMs: 45,
        exitCode: 1,
        signal: null,
        success: false,
        stdout: '',
        stderr: 'FATAL: database port unreachable',
        environment: { platform: 'win32', nodeVersion: 'v22.0.0', nodeMajor: 22 },
        git: { isGit: false }
      };

      const decision = storage.getSurfacingDecision(currentFailure);
      assert.equal(decision.action, 'SURFACE');
      assert.equal(decision.matchType, 'EXACT');
      assert.ok(decision.bestCandidate);
      assert.equal(decision.bestCandidate.change, 'Started local postgres service');
      assert.equal(decision.bestCandidate.isStale, false);
      assert.equal(decision.bestCandidate.isContradicted, false);
    } finally {
      if (storage) storage.close();
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('returns CAUTION when verified fix exists but environment is STALE (runtime major bump)', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-surf-stale-'));
    let storage = null;
    try {
      storage = new StorageEngine(tmpDir).init();

      // Historical failure verified under Node v20
      const inc1 = storage.saveRecord({
        command: 'node',
        args: ['server.js'],
        fullCommand: 'node server.js',
        cwd: tmpDir,
        durationMs: 50,
        exitCode: 1,
        signal: null,
        success: false,
        stdout: '',
        stderr: 'TypeError: fetch is not a function',
        environment: { platform: 'linux', nodeVersion: 'v20.10.0', nodeMajor: 20 },
        git: { isGit: false }
      });

      storage.addRecoveryAttempt(inc1.id, {
        cause: 'Node 20 fetch polyfill missing',
        change: 'Added node-fetch require',
        verifyCmd: 'node -e "process.exit(0);"',
        baselineFailed: true
      });

      storage.recordVerificationRun(inc1.id, 1, {
        command: 'node -e "process.exit(0);"',
        exitCode: 0,
        durationMs: 20,
        output: 'OK'
      });

      // Current failure running under Node v24 (Major version bump -> STALE!)
      const currentFailure = {
        command: 'node',
        args: ['server.js'],
        fullCommand: 'node server.js',
        cwd: tmpDir,
        durationMs: 50,
        exitCode: 1,
        signal: null,
        success: false,
        stdout: '',
        stderr: 'TypeError: fetch is not a function',
        environment: { platform: 'linux', nodeVersion: 'v24.0.0', nodeMajor: 24 },
        git: { isGit: false }
      };

      const decision = storage.getSurfacingDecision(currentFailure);
      assert.equal(decision.action, 'CAUTION', 'Must abstain from confident SURFACE when environment is stale');
      assert.ok(decision.bestCandidate.isStale);
      assert.ok(decision.reason.includes('environment changed'));
    } finally {
      if (storage) storage.close();
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('evaluates per-recovery candidates: selects compatible recovery over stale recovery within same incident history', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-surf-per-rec-'));
    let storage = null;
    try {
      storage = new StorageEngine(tmpDir).init();

      // Incident 1 on linux (stale relative to win32)
      const inc1 = storage.saveRecord({
        command: 'python',
        args: ['app.py'],
        fullCommand: 'python app.py',
        cwd: tmpDir,
        durationMs: 100,
        exitCode: 1,
        signal: null,
        success: false,
        stdout: '',
        stderr: 'ModuleNotFoundError: No module named requests',
        environment: { platform: 'linux', nodeMajor: 22 },
        git: { isGit: false }
      });

      storage.addRecoveryAttempt(inc1.id, {
        cause: 'Missing requests on linux',
        change: 'pip install requests (linux)',
        verifyCmd: 'python -c "import requests"',
        baselineFailed: true
      });
      storage.recordVerificationRun(inc1.id, 1, {
        command: 'python -c "import requests"',
        exitCode: 0,
        durationMs: 25,
        output: ''
      });

      // Incident 2 on win32 (compatible with current win32!)
      const inc2 = storage.saveRecord({
        command: 'python',
        args: ['app.py'],
        fullCommand: 'python app.py',
        cwd: tmpDir,
        durationMs: 100,
        exitCode: 1,
        signal: null,
        success: false,
        stdout: '',
        stderr: 'ModuleNotFoundError: No module named requests',
        environment: { platform: 'win32', nodeMajor: 22 },
        git: { isGit: false }
      });

      storage.addRecoveryAttempt(inc2.id, {
        cause: 'Missing requests on windows',
        change: 'py -m pip install requests',
        verifyCmd: 'python -c "import requests"',
        baselineFailed: true
      });
      storage.recordVerificationRun(inc2.id, 1, {
        command: 'python -c "import requests"',
        exitCode: 0,
        durationMs: 25,
        output: ''
      });

      // Current failure running on win32
      const currentFailure = {
        command: 'python',
        args: ['app.py'],
        fullCommand: 'python app.py',
        cwd: tmpDir,
        durationMs: 80,
        exitCode: 1,
        signal: null,
        success: false,
        stdout: '',
        stderr: 'ModuleNotFoundError: No module named requests',
        environment: { platform: 'win32', nodeMajor: 22 },
        git: { isGit: false }
      };

      const decision = storage.getSurfacingDecision(currentFailure);
      assert.equal(decision.action, 'SURFACE');
      assert.ok(decision.bestCandidate);
      // Evaluated per-recovery candidate: selected the win32 compatible fix!
      assert.equal(decision.bestCandidate.change, 'py -m pip install requests');
      assert.equal(decision.bestCandidate.isStale, false);
    } finally {
      if (storage) storage.close();
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('surfaces CAUTION when only failed approaches exist in negative memory (no verified fix)', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-surf-neg-mem-'));
    let storage = null;
    try {
      storage = new StorageEngine(tmpDir).init();

      // Incident with 2 failed attempts
      const inc = storage.saveRecord({
        command: 'npm',
        args: ['start'],
        fullCommand: 'npm start',
        cwd: tmpDir,
        durationMs: 100,
        exitCode: 1,
        signal: null,
        success: false,
        stdout: '',
        stderr: 'EADDRINUSE: address already in use :::8080',
        environment: { platform: 'win32' },
        git: { isGit: false }
      });

      storage.addRecoveryAttempt(inc.id, {
        cause: 'Wrong port',
        change: 'Changed port to 8081',
        verifyCmd: 'node -e "process.exit(1);"'
      });
      storage.recordVerificationRun(inc.id, 1, {
        command: 'node -e "process.exit(1);"',
        exitCode: 1,
        durationMs: 20,
        output: 'Failed'
      });

      // Current failure
      const current = {
        command: 'npm',
        args: ['start'],
        fullCommand: 'npm start',
        cwd: tmpDir,
        durationMs: 90,
        exitCode: 1,
        signal: null,
        success: false,
        stdout: '',
        stderr: 'EADDRINUSE: address already in use :::8080',
        environment: { platform: 'win32' },
        git: { isGit: false }
      };

      const decision = storage.getSurfacingDecision(current);
      assert.equal(decision.action, 'CAUTION');
      assert.equal(decision.bestCandidate, null);
      assert.equal(decision.relevantFailedApproaches.length, 1);
      assert.equal(decision.relevantFailedApproaches[0].change, 'Changed port to 8081');
      assert.ok(decision.reason.includes('failed approach'));
    } finally {
      if (storage) storage.close();
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('does not SURFACE unverified external imported recoveries until locally verified', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-surf-ext-'));
    let storage = null;
    try {
      storage = new StorageEngine(tmpDir).init();

      // Create an incident with an imported external recovery attempt
      const inc = storage.saveRecord({
        command: 'cargo',
        args: ['build'],
        fullCommand: 'cargo build',
        cwd: tmpDir,
        durationMs: 120,
        exitCode: 101,
        signal: null,
        success: false,
        stdout: '',
        stderr: 'error[E0432]: unresolved import `foo`',
        environment: { platform: 'linux', nodeVersion: 'v22.0.0', nodeMajor: 22 },
        git: { isGit: false }
      });

      storage.addRecoveryAttempt(inc.id, {
        cause: 'Missing crate foo',
        change: 'Added foo = "1.0" to Cargo.toml',
        verifyCmd: 'cargo check',
        isExternal: true,
        baselineFailed: true,
        evidenceQuality: 'EXTERNAL_VERIFIED'
      });

      const currentFailure = {
        command: 'cargo',
        args: ['build'],
        fullCommand: 'cargo build',
        cwd: tmpDir,
        durationMs: 100,
        exitCode: 101,
        signal: null,
        success: false,
        stdout: '',
        stderr: 'error[E0432]: unresolved import `foo`',
        environment: { platform: 'linux', nodeVersion: 'v22.0.0', nodeMajor: 22 },
        git: { isGit: false }
      };

      // 1. Before local verification: Must NOT surface external candidate
      const decisionBefore = storage.getSurfacingDecision(currentFailure);
      assert.notEqual(decisionBefore.action, 'SURFACE');

      // 2. Perform local verification
      storage.recordVerificationRun(inc.id, 1, {
        command: 'cargo check',
        exitCode: 0,
        durationMs: 50,
        output: 'Finished dev profile'
      });

      // 3. After local verification: Now it surfaces confidently
      const decisionAfter = storage.getSurfacingDecision(currentFailure);
      assert.equal(decisionAfter.action, 'SURFACE');
      assert.ok(decisionAfter.bestCandidate);
      assert.equal(decisionAfter.bestCandidate.change, 'Added foo = "1.0" to Cargo.toml');
      assert.equal(decisionAfter.bestCandidate.isLocallyVerified, true);
    } finally {
      if (storage) storage.close();
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });
});
