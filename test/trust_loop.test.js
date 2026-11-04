import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs';
import { runCLI } from '../src/cli.js';
import { StorageEngine } from '../src/storage/store.js';
import {
  IncidentStatus,
  RecoveryAttemptStatus,
  isValidIncidentTransition,
  isValidAttemptTransition
} from '../src/storage/state.js';
import { applyEventToRecordMap } from '../src/storage/projection.js';

function createMockIO({ env = {}, isTTY = false, cwd = process.cwd() } = {}) {
  let stdoutData = '';
  let stderrData = '';

  const stdout = {
    write: (chunk) => {
      stdoutData += chunk;
      return true;
    }
  };

  const stderr = {
    write: (chunk) => {
      stderrData += chunk;
      return true;
    }
  };

  return {
    io: {
      stdout,
      stderr,
      stdin: {},
      env,
      isTTY,
      cwd
    },
    getStdout: () => stdoutData,
    getStderr: () => stderrData
  };
}

describe('Trust Loop State Machine & Verification (src/storage/state.js)', () => {
  test('validates legal and illegal state transitions', () => {
    // Valid incident transitions
    assert.equal(isValidIncidentTransition(IncidentStatus.OBSERVED, IncidentStatus.OPEN), true);
    assert.equal(isValidIncidentTransition(IncidentStatus.OPEN, IncidentStatus.RECOVERED), true);
    assert.equal(isValidIncidentTransition(IncidentStatus.RECOVERED, IncidentStatus.OPEN), true);
    assert.equal(isValidIncidentTransition(IncidentStatus.REGRESSED, IncidentStatus.OPEN), true);

    // Illegal incident transitions
    assert.equal(isValidIncidentTransition(IncidentStatus.OBSERVED, IncidentStatus.RECOVERED), false);
    assert.equal(isValidIncidentTransition(IncidentStatus.OBSERVED, 'UNKNOWN_STATE'), false);

    // Valid recovery attempt transitions
    assert.equal(isValidAttemptTransition(RecoveryAttemptStatus.PROPOSED, RecoveryAttemptStatus.ATTEMPTED), true);
    assert.equal(isValidAttemptTransition(RecoveryAttemptStatus.ATTEMPTED, RecoveryAttemptStatus.VERIFIED), true);
    assert.equal(isValidAttemptTransition(RecoveryAttemptStatus.ATTEMPTED, RecoveryAttemptStatus.FAILED), true);

    // Illegal recovery attempt transitions (terminal states cannot transition)
    assert.equal(isValidAttemptTransition(RecoveryAttemptStatus.VERIFIED, RecoveryAttemptStatus.FAILED), false);
    assert.equal(isValidAttemptTransition(RecoveryAttemptStatus.FAILED, RecoveryAttemptStatus.VERIFIED), false);
  });

  test('executes complete Trust Loop: OBSERVED -> SUSPECTED -> FIXED -> VERIFIED -> REGRESSED', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-loop-test-'));
    try {
      const rootFlag = `--root=${tmpDir}`;
      const store = new StorageEngine(path.join(tmpDir, '.rewind'));

      // Step 1: Run failing command -> creates Incident #1 (OBSERVED)
      const mock1 = createMockIO({ cwd: tmpDir });
      const code1 = await runCLI([rootFlag, 'run', process.execPath, '-e', 'console.error("Crash in auth handler"); process.exit(1);'], mock1.io);
      assert.equal(code1, 1);

      store.init();
      const inc1 = store.getRecord('1');
      assert.ok(inc1);
      assert.equal(inc1.id, '1');
      assert.equal(inc1.status, IncidentStatus.OBSERVED);
      assert.ok(inc1.fingerprint);

      // Step 2: Record suspected cause -> transitions to OPEN/SUSPECTED
      const mock2 = createMockIO({ cwd: tmpDir });
      const code2 = await runCLI([rootFlag, 'recover', '1', '--cause', 'Token validation failed'], mock2.io);
      assert.equal(code2, 0);

      store.rebuildIndex();
      const inc1Suspected = store.getRecord('1');
      assert.equal(inc1Suspected.status, IncidentStatus.OPEN);
      assert.equal(inc1Suspected.recoveryAttempts.length, 1);
      assert.equal(inc1Suspected.recoveryAttempts[0].cause, 'Token validation failed');

      // Step 3: Record change and explicit verification command with proven baseline failure
      const mock3 = createMockIO({ cwd: tmpDir });
      const code3 = await runCLI([
        rootFlag,
        'recover',
        '1',
        '--change',
        'Added missing token check',
        '--verify-cmd',
        `"${process.execPath}" -e "process.exit(0);"`,
        '--baseline-failed'
      ], mock3.io);
      assert.equal(code3, 0);

      store.rebuildIndex();
      const inc1Fixed = store.getRecord('1');
      assert.equal(inc1Fixed.status, IncidentStatus.OPEN);
      assert.equal(inc1Fixed.recoveryAttempts.length, 2);
      assert.equal(inc1Fixed.recoveryAttempts[1].change, 'Added missing token check');

      // Step 4: Execute rewind verify 1 -> transitions to VERIFIED/RECOVERED with red-to-green proof
      const mock4 = createMockIO({ cwd: tmpDir });
      const code4 = await runCLI([rootFlag, 'verify', '1', '--yes'], mock4.io);
      assert.equal(code4, 0);

      store.rebuildIndex();
      const inc1Verified = store.getRecord('1');
      assert.equal(inc1Verified.status, IncidentStatus.RECOVERED);
      assert.ok(inc1Verified.verification);
      assert.equal(inc1Verified.verification.exitCode, 0);

      // Step 5: Reproduce the identical failure -> creates Incident #2 marked as REGRESSED
      const mock5 = createMockIO({ cwd: tmpDir });
      const code5 = await runCLI([rootFlag, 'run', process.execPath, '-e', 'console.error("Crash in auth handler"); process.exit(1);'], mock5.io);
      assert.equal(code5, 1);

      store.rebuildIndex();
      const inc2 = store.getRecord('2');
      assert.ok(inc2);
      assert.equal(inc2.id, '2');
      assert.equal(inc2.status, IncidentStatus.REGRESSED);
      assert.equal(inc2.regressionOf, '1');
      assert.equal(inc2.fingerprint, inc1.fingerprint);
      assert.ok(mock5.getStderr().includes('REGRESSION'));
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('rewind verify fails when verification command exits non-zero', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-verify-fail-'));
    try {
      const rootFlag = `--root=${tmpDir}`;

      // 1. Create failure
      const mock1 = createMockIO({ cwd: tmpDir });
      await runCLI([rootFlag, 'run', process.execPath, '-e', 'console.error("DB down"); process.exit(1);'], mock1.io);

      // 2. Record fix with a verification command that will FAIL
      const mock2 = createMockIO({ cwd: tmpDir });
      await runCLI([
        rootFlag,
        'recover',
        '1',
        '--cause',
        'Bad port',
        '--change',
        'Port 5432',
        '--verify-cmd',
        `"${process.execPath}" -e "console.error('Still down'); process.exit(44);"`
      ], mock2.io);

      // 3. Attempt verification
      const mock3 = createMockIO({ cwd: tmpDir });
      const verifyExitCode = await runCLI([rootFlag, 'verify', '1', '--yes'], mock3.io);

      assert.equal(verifyExitCode, 44);
      assert.ok(mock3.getStderr().includes('NOT VERIFIED'));

      const store = new StorageEngine(path.join(tmpDir, '.rewind')).init();
      const record = store.getRecord('1');
      assert.equal(record.status, IncidentStatus.OPEN); // Did NOT promote to VERIFIED
      assert.equal(record.recoveryAttempts[0].status, 'FAILED'); // Preserved in negative memory
      assert.equal(record.verification.exitCode, 44);
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('rejects verifying an unknown incident ID', async () => {
    const mock = createMockIO();
    const exitCode = await runCLI(['verify', '99999'], mock.io);
    assert.equal(exitCode, 1);
    assert.ok(mock.getStderr().includes('Incident #99999 not found'));
  });

  test('rejects verifying an incident with no stored verification command', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-no-cmd-'));
    try {
      const rootFlag = `--root=${tmpDir}`;
      const mock1 = createMockIO({ cwd: tmpDir });
      await runCLI([rootFlag, 'run', process.execPath, '-e', 'console.error("err"); process.exit(1);'], mock1.io);

      // Try verify directly without recover
      const mock2 = createMockIO({ cwd: tmpDir });
      const code = await runCLI([rootFlag, 'verify', '1'], mock2.io);
      assert.equal(code, 2);
      assert.ok(mock2.getStderr().includes('has no explicit verification command recorded'));
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('rejects verifying an already VERIFIED incident', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-double-verify-'));
    try {
      const rootFlag = `--root=${tmpDir}`;
      const mock1 = createMockIO({ cwd: tmpDir });
      await runCLI([rootFlag, 'run', process.execPath, '-e', 'console.error("err"); process.exit(1);'], mock1.io);

      const mock2 = createMockIO({ cwd: tmpDir });
      await runCLI([rootFlag, 'recover', '1', '--change', 'fix', '--verify-cmd', `"${process.execPath}" -e "process.exit(0);"`], mock2.io);

      const mock3 = createMockIO({ cwd: tmpDir });
      const code3 = await runCLI([rootFlag, 'verify', '1', '--yes'], mock3.io);
      assert.equal(code3, 0);

      // Try verify again
      const mock4 = createMockIO({ cwd: tmpDir });
      const code4 = await runCLI([rootFlag, 'verify', '1', '--yes'], mock4.io);
      assert.equal(code4, 0);
      assert.ok(mock4.getStdout().includes('is already verified and sealed'));
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('rewind verify handles compound shell verification commands cleanly', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-compound-verify-'));
    try {
      const rootFlag = `--root=${tmpDir}`;
      const mock1 = createMockIO({ cwd: tmpDir });
      await runCLI([rootFlag, 'run', process.execPath, '-e', 'console.error("fail"); process.exit(1);'], mock1.io);

      const mock2 = createMockIO({ cwd: tmpDir });
      await runCLI([
        rootFlag,
        'recover',
        '1',
        '--change',
        'compound fix',
        '--verify-cmd',
        `"${process.execPath}" -e "process.exit(0);" && "${process.execPath}" -e "process.exit(0);"`
      ], mock2.io);

      const mock3 = createMockIO({ cwd: tmpDir });
      const code3 = await runCLI([rootFlag, 'verify', '1', '--shell', '--yes'], mock3.io);
      assert.equal(code3, 0);
      assert.ok(mock3.getStdout().includes('RECOVERY VERIFIED'));
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('rewind verify terminates cleanly and flags timeout when verification exceeds limit', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-timeout-verify-'));
    try {
      const rootFlag = `--root=${tmpDir}`;
      const mock1 = createMockIO({ cwd: tmpDir });
      await runCLI([rootFlag, 'run', process.execPath, '-e', 'console.error("fail"); process.exit(1);'], mock1.io);

      const mock2 = createMockIO({ cwd: tmpDir });
      // Verification command sleeps for 5 seconds
      await runCLI([
        rootFlag,
        'recover',
        '1',
        '--change',
        'slow fix',
        '--verify-cmd',
        `"${process.execPath}" -e "setTimeout(() => process.exit(0), 5000);"`
      ], mock2.io);

      // Verify with a 200ms timeout
      const mock3 = createMockIO({ cwd: tmpDir });
      const code3 = await runCLI([rootFlag, 'verify', '1', '--timeout', '200', '--yes'], mock3.io);
      assert.notEqual(code3, 0);
      assert.ok(mock3.getStderr().includes('TIMED OUT') || mock3.getStderr().includes('timed out'));
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('applyEventToRecordMap enforces state transition invariants and rejects illegal transitions', () => {
    const map = new Map();
    // 1. Initial observation
    applyEventToRecordMap(map, {
      sequence: 1,
      type: 'failure.observed',
      incidentId: '42',
      timestamp: '2026-01-01T00:00:00.000Z',
      payload: { command: 'node test.js' }
    });
    assert.equal(map.get('42').status, IncidentStatus.OBSERVED);

    // 2. Propose recovery -> OPEN
    applyEventToRecordMap(map, {
      sequence: 2,
      type: 'recovery.proposed',
      incidentId: '42',
      timestamp: '2026-01-01T00:01:00.000Z',
      payload: { attemptId: 1, change: 'fixed bug' }
    });
    assert.equal(map.get('42').status, IncidentStatus.OPEN);

    // 3. Mark FIXED
    applyEventToRecordMap(map, {
      sequence: 3,
      type: 'recovery.fixed',
      incidentId: '42',
      timestamp: '2026-01-01T00:02:00.000Z',
      payload: { attemptId: 1 }
    });
    assert.equal(map.get('42').recoveryAttempts[0].status, RecoveryAttemptStatus.FIXED);

    // 4. Verify -> VERIFIED & RECOVERED
    applyEventToRecordMap(map, {
      sequence: 4,
      type: 'verification.run',
      incidentId: '42',
      timestamp: '2026-01-01T00:03:00.000Z',
      payload: { attemptId: 1, exitCode: 0 }
    });
    assert.equal(map.get('42').status, IncidentStatus.RECOVERED);
    assert.equal(map.get('42').recoveryAttempts[0].status, RecoveryAttemptStatus.VERIFIED);

    // 5. Attempt illegal transition on sealed attempt (trying to mark a VERIFIED attempt as FIXED)
    assert.throws(() => {
      applyEventToRecordMap(map, {
        sequence: 5,
        type: 'recovery.fixed',
        incidentId: '42',
        timestamp: '2026-01-01T00:04:00.000Z',
        payload: { attemptId: 1 }
      });
    }, /Illegal recovery attempt state transition/);

    // 6. Resolve incident -> RESOLVED
    applyEventToRecordMap(map, {
      sequence: 6,
      type: 'incident.resolved',
      incidentId: '42',
      timestamp: '2026-01-01T00:05:00.000Z'
    });
    assert.equal(map.get('42').status, IncidentStatus.RESOLVED);

    // 7. Attempt illegal incident transition: RESOLVED directly to RECOVERED without re-opening
    assert.throws(() => {
      applyEventToRecordMap(map, {
        sequence: 7,
        type: 'verification.run',
        incidentId: '42',
        timestamp: '2026-01-01T00:06:00.000Z',
        payload: { attemptId: 1, exitCode: 0 }
      });
    }, /Illegal incident state transition/);
  });
});
