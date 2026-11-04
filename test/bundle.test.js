import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { PassThrough, Writable } from 'node:stream';
import { StorageEngine } from '../src/storage/store.js';
import { IncidentStatus, RecoveryAttemptStatus, EvidenceQuality } from '../src/storage/state.js';
import {
  exportRecoveryBundle,
  importRecoveryBundle,
  stripMachinePaths,
  sanitizeBundleIncident,
  CURRENT_BUNDLE_SCHEMA_VERSION,
  BUNDLE_FORMAT_IDENTIFIER
} from '../src/sharing/bundle.js';
import { runCLI } from '../src/cli.js';
import { stripAnsi } from '../src/sanitizer.js';

function createMockIO() {
  let stdoutData = '';
  let stderrData = '';

  const stdout = new Writable({
    write(chunk, encoding, callback) {
      stdoutData += chunk.toString();
      callback();
    }
  });

  const stderr = new Writable({
    write(chunk, encoding, callback) {
      stderrData += chunk.toString();
      callback();
    }
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

describe('Project-Level Shared Recovery Bundles (test/bundle.test.js)', () => {
  let tempDir;
  let storage;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-bundle-test-'));
    storage = new StorageEngine(path.join(tempDir, '.rewind'));
    storage.init();
  });

  afterEach(() => {
    try {
      try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch {}
    } catch {
      // Ignore
    }
  });

  describe('Path & Secret Sanitization', () => {
    test('stripMachinePaths removes workspace root and user home paths cleanly', () => {
      const sample = `Error in /Users/developer/project/src/index.js at line 42`;
      const sanitized = stripMachinePaths(sample, '/Users/developer/project');
      assert.doesNotMatch(sanitized, /\/Users\/developer\/project/);
      assert.match(sanitized, /<WORKSPACE_ROOT>/);
    });

    test('sanitizeBundleIncident redacts secrets and removes machine identifiers', () => {
      const record = {
        id: '1',
        fingerprint: 'abcd1234ef567890',
        command: 'curl',
        args: ['-H', 'Authorization: Bearer sk-1234567890123456789012345', 'https://api.com'],
        fullCommand: 'curl -H "Authorization: Bearer sk-1234567890123456789012345" https://api.com',
        cwd: tempDir,
        startTime: '2026-08-30T00:00:00.000Z',
        endTime: '2026-08-30T00:00:01.000Z',
        durationMs: 100,
        exitCode: 1,
        stderr: `Failed with token sk-1234567890123456789012345 at ${tempDir}\\app.js`,
        normalizedError: 'Failed with token',
        diagnostic: {
          language: 'NODE',
          errorType: 'AuthError',
          message: 'Invalid auth token sk-1234567890123456789012345',
          sourceFile: path.join(tempDir, 'src/auth.js')
        },
        environment: {
          platform: 'win32',
          arch: 'x64',
          nodeVersion: 'v22.18.0',
          nodeMajor: 22,
          osRelease: '10.0.26200',
          envKeysHash: 'secret_hash_123'
        },
        git: { isGit: true, branch: 'main' },
        recoveryAttempts: [
          {
            id: 1,
            cause: 'Expired API token sk-1234567890123456789012345',
            change: 'Refreshed API credentials',
            verifyCmd: 'npm test',
            status: 'VERIFIED',
            verificationRuns: [
              {
                id: 1,
                exitCode: 0,
                durationMs: 50,
                output: 'Auth verified: OK',
                outputHash: 'hash123',
                result: 'PASSED'
              }
            ]
          }
        ]
      };

      const sanitized = sanitizeBundleIncident(record, tempDir);

      assert.ok(sanitized);
      assert.doesNotMatch(sanitized.fullCommand, /sk-12345/);
      assert.doesNotMatch(sanitized.stderr, /sk-12345/);
      assert.doesNotMatch(sanitized.diagnostic.message, /sk-12345/);
      assert.doesNotMatch(sanitized.recoveryAttempts[0].cause, /sk-12345/);

      // Verify absolute path removal
      assert.doesNotMatch(sanitized.diagnostic.sourceFile, new RegExp(tempDir.replace(/\\/g, '\\\\')));
      assert.match(sanitized.diagnostic.sourceFile, /<WORKSPACE_ROOT>/);

      // Verify machine identifiers omitted from environment
      assert.equal(sanitized.environment.envKeysHash, undefined);
      assert.equal(sanitized.environment.platform, 'win32');
    });
  });

  describe('Export Recovery Bundle', () => {
    test('exports only verified incidents by default into portable JSON bundle', () => {
      // Incident 1: Verified
      const inc1 = storage.saveRecord({
        command: 'npm',
        args: ['test'],
        fullCommand: 'npm test',
        exitCode: 1,
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 50,
        stderr: 'Database timeout',
        cwd: tempDir
      });
      storage.addRecoveryAttempt(inc1.id, {
        cause: 'DB pool size too small',
        change: 'Increased pool size',
        verifyCmd: 'npm test'
      });
      storage.recordVerificationRun(inc1.id, 1, {
        command: 'npm test',
        exitCode: 0,
        durationMs: 40,
        output: 'All tests passed'
      });

      // Incident 2: Unverified open failure
      storage.saveRecord({
        command: 'cargo',
        args: ['build'],
        fullCommand: 'cargo build',
        exitCode: 101,
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 80,
        stderr: 'error: unresolved import',
        cwd: tempDir
      });

      const bundlePath = path.join(tempDir, 'shared-bundle.json');
      const { bundle, totalIncidents, totalVerifiedRecoveries } = exportRecoveryBundle({
        storage,
        rootDir: tempDir,
        outputPath: bundlePath,
        includeUnverified: false
      });

      assert.equal(totalIncidents, 1);
      assert.equal(totalVerifiedRecoveries, 1);
      assert.equal(bundle.format, BUNDLE_FORMAT_IDENTIFIER);
      assert.equal(bundle.schemaVersion, CURRENT_BUNDLE_SCHEMA_VERSION);
      assert.ok(fs.existsSync(bundlePath));

      const fileContent = JSON.parse(fs.readFileSync(bundlePath, 'utf8'));
      assert.equal(fileContent.incidents.length, 1);
      assert.equal(fileContent.incidents[0].command, 'npm');
      assert.equal(fileContent.incidents[0].recoveryAttempts[0].status, 'VERIFIED');
    });

    test('exports all incidents when includeUnverified is true', () => {
      storage.saveRecord({
        command: 'pytest',
        args: ['test_api.py'],
        fullCommand: 'pytest test_api.py',
        exitCode: 1,
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 60,
        stderr: 'AssertionError: test failed',
        cwd: tempDir
      });

      const bundlePath = path.join(tempDir, 'all-bundle.json');
      const { totalIncidents } = exportRecoveryBundle({
        storage,
        rootDir: tempDir,
        outputPath: bundlePath,
        includeUnverified: true
      });

      assert.equal(totalIncidents, 1);
    });
  });

  describe('Import Recovery Bundle & Trust Invariants', () => {
    test('imports bundle and marks verified recoveries as VERIFIED (EXTERNAL EVIDENCE)', () => {
      // Create a test bundle
      const bundleData = {
        $schema: 'https://rewind.dev/schemas/v1/shared-recovery.json',
        format: BUNDLE_FORMAT_IDENTIFIER,
        schemaVersion: CURRENT_BUNDLE_SCHEMA_VERSION,
        producerVersion: '0.1.0',
        exportedAt: new Date().toISOString(),
        metadata: {
          totalIncidents: 1,
          totalVerifiedRecoveries: 1
        },
        incidents: [
          {
            originalIncidentId: '1',
            fingerprint: '1122334455667788',
            command: 'node',
            args: ['server.js'],
            fullCommand: 'node server.js',
            normalizedError: 'EADDRINUSE 8080',
            exitCode: 1,
            durationMs: 40,
            startTime: '2026-08-30T01:00:00.000Z',
            endTime: '2026-08-30T01:00:01.000Z',
            stderr: 'Error: listen EADDRINUSE: address already in use :::8080',
            diagnostic: {
              language: 'NODE',
              errorType: 'SystemError',
              errorCode: 'EADDRINUSE',
              message: 'address already in use :::8080'
            },
            environment: { platform: 'linux', nodeVersion: 'v22.0.0' },
            git: { isGit: true, branch: 'main' },
            recoveryAttempts: [
              {
                attemptId: 1,
                cause: 'Port 8080 was occupied by stale zombie process',
                change: 'Killed process on port 8080 and added auto-retry',
                verifyCmd: 'node server.js --check-port',
                status: RecoveryAttemptStatus.VERIFIED,
                verificationEvidence: {
                  runId: 1,
                  exitCode: 0,
                  durationMs: 35,
                  verifiedAt: '2026-08-30T01:05:00.000Z',
                  result: 'PASSED'
                }
              }
            ]
          }
        ]
      };

      const result = importRecoveryBundle({
        storage,
        bundle: bundleData,
        rootDir: tempDir,
        dryRun: false
      });

      assert.equal(result.importedCount, 1);
      assert.equal(result.skippedCount, 0);
      assert.equal(result.totalVerifiedRecoveries, 1);

      storage.rebuildIndex();
      const importedRecord = storage.getRecord('1');
      assert.ok(importedRecord);
      assert.equal(importedRecord.command, 'node');
      assert.equal(importedRecord.status, IncidentStatus.OPEN); // Must remain OPEN until local verification

      const attempt = importedRecord.recoveryAttempts[0];
      assert.ok(attempt);
      assert.equal(attempt.status, RecoveryAttemptStatus.VERIFIED);
      assert.equal(attempt.isExternal, true); // Marked external
      assert.equal(attempt.evidenceQuality, EvidenceQuality.SUPPORTED);
      assert.equal(attempt.verificationRuns.length, 0); // No local verification runs yet
      assert.ok(attempt.externalVerification);
    });

    test('idempotency: skips duplicate bundle records on re-import', () => {
      const bundleData = {
        format: BUNDLE_FORMAT_IDENTIFIER,
        schemaVersion: CURRENT_BUNDLE_SCHEMA_VERSION,
        incidents: [
          {
            fingerprint: 'aabbccddeeff0011',
            command: 'npm',
            args: ['test'],
            fullCommand: 'npm test',
            exitCode: 1,
            stderr: 'Missing env var',
            recoveryAttempts: [
              {
                cause: 'Missing PORT',
                change: 'Added PORT=3000',
                verifyCmd: 'npm test',
                status: 'VERIFIED'
              }
            ]
          }
        ]
      };

      // First import
      const res1 = importRecoveryBundle({ storage, bundle: bundleData, rootDir: tempDir });
      assert.equal(res1.importedCount, 1);
      assert.equal(res1.skippedCount, 0);

      // Second import
      const res2 = importRecoveryBundle({ storage, bundle: bundleData, rootDir: tempDir });
      assert.equal(res2.importedCount, 0);
      assert.equal(res2.skippedCount, 1);
    });

    test('rejects bundle with foreign/newer schemaVersion with actionable upgrade message', () => {
      const futureBundle = {
        format: BUNDLE_FORMAT_IDENTIFIER,
        schemaVersion: 99,
        incidents: []
      };

      assert.throws(
        () => importRecoveryBundle({ storage, bundle: futureBundle, rootDir: tempDir }),
        /Unsupported bundle schema version: 99/
      );
    });

    test('rejects corrupted bundle with invalid JSON syntax', () => {
      const corruptFile = path.join(tempDir, 'corrupt.json');
      fs.writeFileSync(corruptFile, '{ invalid json syntax !!!', 'utf8');

      assert.throws(
        () => importRecoveryBundle({ storage, bundle: corruptFile, rootDir: tempDir }),
        /Corrupted bundle file/
      );
    });
  });

  describe('Local Re-Verification of Imported Recovery', () => {
    test('local verification upgrades imported external evidence to VERIFIED LOCALLY and RECOVERED', async () => {
      // 1. Import external verified recovery
      const bundleData = {
        format: BUNDLE_FORMAT_IDENTIFIER,
        schemaVersion: CURRENT_BUNDLE_SCHEMA_VERSION,
        incidents: [
          {
            fingerprint: '9988776655443322',
            command: 'node',
            args: ['app.js'],
            fullCommand: 'node app.js',
            exitCode: 1,
            stderr: 'Connection timeout',
            recoveryAttempts: [
              {
                cause: 'Database disconnected',
                change: 'Reconnected database client',
                verifyCmd: 'node -e "process.exit(0);"',
                status: 'VERIFIED'
              }
            ]
          }
        ]
      };

      importRecoveryBundle({ storage, bundle: bundleData, rootDir: tempDir });
      storage.rebuildIndex();

      const initialRecord = storage.getRecord('1');
      assert.equal(initialRecord.status, IncidentStatus.OPEN);
      assert.equal(initialRecord.recoveryAttempts[0].isExternal, true);

      // 2. Run local verification via rewind verify 1
      const { stdin, stdout, stderr } = createMockIO();
      const exitCode = await runCLI(['verify', '1', '--root', tempDir, '--yes'], {
        stdin,
        stdout,
        stderr,
        isTTY: false
      });

      assert.equal(exitCode, 0);

      storage.rebuildIndex();
      const verifiedRecord = storage.getRecord('1');
      assert.equal(verifiedRecord.status, IncidentStatus.RECOVERED); // Upgraded to RECOVERED
      assert.equal(verifiedRecord.recoveryAttempts[0].isExternal, false); // Local verification established
      assert.equal(verifiedRecord.recoveryAttempts[0].evidenceQuality, EvidenceQuality.DIRECT);
      assert.equal(verifiedRecord.recoveryAttempts[0].verificationRuns.length, 1);
      assert.equal(verifiedRecord.recoveryAttempts[0].verificationRuns[0].result, 'PASSED');
    });
  });

  describe('CLI End-to-End Commands (export-shared & import-shared)', () => {
    test('rewind export-shared and rewind import-shared work end-to-end via CLI', async () => {
      // 1. Create a verified incident in original ledger
      const rec = storage.saveRecord({
        command: 'npm',
        args: ['run', 'build'],
        fullCommand: 'npm run build',
        exitCode: 1,
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 120,
        stderr: 'SyntaxError: Unexpected token',
        cwd: tempDir
      });
      storage.addRecoveryAttempt(rec.id, {
        cause: 'Trailing comma in tsconfig',
        change: 'Removed trailing comma',
        verifyCmd: 'npm run build'
      });
      storage.recordVerificationRun(rec.id, 1, {
        command: 'npm run build',
        exitCode: 0,
        durationMs: 80,
        output: 'Build succeeded'
      });

      const bundleFile = path.join(tempDir, 'export-test.json');

      // 2. Export bundle via CLI
      {
        const { stdin, stdout, stderr, getStdout } = createMockIO();
        const exitCode = await runCLI(['export-shared', '-o', bundleFile, '--root', tempDir], {
          stdin,
          stdout,
          stderr,
          isTTY: false
        });
        assert.equal(exitCode, 0);
        const out = stripAnsi(getStdout());
        assert.match(out, /SHARED RECOVERY BUNDLE EXPORTED/);
        assert.match(out, /Verified Recoveries/);
      }

      // 3. Create fresh new ledger in second temporary directory
      const teammateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-teammate-'));
      const teammateStorage = new StorageEngine(path.join(teammateDir, '.rewind'));
      teammateStorage.init();

      // 4. Import bundle in teammate directory
      {
        const { stdin, stdout, stderr, getStdout } = createMockIO();
        const exitCode = await runCLI(['import-shared', bundleFile, '--root', teammateDir], {
          stdin,
          stdout,
          stderr,
          isTTY: false
        });
        assert.equal(exitCode, 0);
        const out = stripAnsi(getStdout());
        assert.match(out, /SHARED RECOVERY BUNDLE IMPORTED/);
        assert.match(out, /EXTERNAL EVIDENCE/);
      }

      // 5. Inspect imported record via show in teammate ledger
      {
        const { stdin, stdout, stderr, getStdout } = createMockIO();
        const exitCode = await runCLI(['show', '1', '--root', teammateDir], {
          stdin,
          stdout,
          stderr,
          isTTY: false
        });
        assert.equal(exitCode, 0);
        const out = stripAnsi(getStdout());
        assert.match(out, /External Evidence — Unverified Locally/);
        assert.match(out, /Imported from shared recovery bundle/);
      }

      try { fs.rmSync(teammateDir, { recursive: true, force: true }); } catch {}
    });
  });
});
