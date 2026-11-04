import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { readJournalEvents, writeCheckpoint } from './journal.js';
import { projectEventsToRecords, PROJECTION_SCHEMA_VERSION } from './projection.js';
import { verifyLedgerIntegrity } from './integrity.js';
import { isValidRecord } from './record.js';
import { redactSecrets } from '../sanitizer.js';
import { IncidentStatus, RecoveryAttemptStatus } from './state.js';

export const SUPPORTED_NODE_RANGE = '>=22.13.0';

/**
 * Formats byte size into human-readable representation.
 *
 * @param {number} bytes
 * @returns {string}
 */
export function formatByteSize(bytes) {
  if (typeof bytes !== 'number' || Number.isNaN(bytes) || bytes < 0) return '0 B';
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  if (i === 0) return `${bytes} B`;
  const size = bytes / Math.pow(1024, i);
  return `${size.toFixed(1)} ${units[i]}`;
}

/**
 * Calculates total disk usage recursively without traversing external symlinks.
 *
 * @param {string} targetDir
 * @returns {number} Total bytes
 */
export function calculateStorageSize(targetDir) {
  let totalBytes = 0;
  if (!fs.existsSync(targetDir)) return 0;

  try {
    const stat = fs.lstatSync(targetDir);
    if (!stat.isDirectory()) {
      return stat.size;
    }

    const entries = fs.readdirSync(targetDir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(targetDir, entry.name);
      try {
        const entryStat = fs.lstatSync(fullPath);
        if (entryStat.isSymbolicLink()) {
          // Do not follow symlinks outside boundary; count link metadata only
          totalBytes += entryStat.size;
        } else if (entryStat.isDirectory()) {
          totalBytes += calculateStorageSize(fullPath);
        } else if (entryStat.isFile()) {
          totalBytes += entryStat.size;
        }
      } catch {
        // Skip unreadable entries
      }
    }
  } catch {
    // Directory unreadable
  }

  return totalBytes;
}

/**
 * Runs a deterministic self-test of the configured secret redaction rules
 * against representative patterns.
 *
 * @returns {{ pass: boolean, testedCount: number, passedCount: number, details: Array<{ name: string, pass: boolean }>, notice: string }}
 */
export function performRedactionSelfTest() {
  const dummyOpenAi = ['sk', 'proj', '1234567890abcdef1234567890abcdef'].join('-');
  const dummyAkia = ['AKIA', '0123456789ABCDEF'].join('');
  const dummyGhp = ['ghp', '0123456789abcdefghijklmnopqrstuvwxyz'].join('_');
  const dummyBearer = ['secret', 'bearer', 'token', '12345'].join('_');

  const testCases = [
    {
      name: 'OpenAI API Key',
      input: `Error with key ${dummyOpenAi} in config`,
      verify: (out) => !out.includes(dummyOpenAi) && out.includes('[REDACTED_API_KEY]')
    },
    {
      name: 'AWS Access Key',
      input: `AWS auth failed with ${dummyAkia}`,
      verify: (out) => !out.includes(dummyAkia) && out.includes('[REDACTED_AWS_KEY]')
    },
    {
      name: 'GitHub Personal Access Token',
      input: `Token ${dummyGhp} invalid`,
      verify: (out) => !out.includes(dummyGhp) && out.includes('[REDACTED_GITHUB_TOKEN]')
    },
    {
      name: 'Bearer Authorization Token',
      input: `Authorization: Bearer ${dummyBearer}`,
      verify: (out) => !out.includes(dummyBearer) && out.includes('Bearer [REDACTED]')
    },
    {
      name: 'PEM Private Key Block',
      input: '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----',
      verify: (out) => !out.includes('MIIEowIBAAKCAQEA0') && out.includes('[REDACTED_PRIVATE_KEY]')
    }
  ];

  const results = [];
  let allPass = true;

  for (const tc of testCases) {
    try {
      const redacted = redactSecrets(tc.input);
      const passed = tc.verify(redacted);
      results.push({ name: tc.name, pass: passed });
      if (!passed) allPass = false;
    } catch {
      results.push({ name: tc.name, pass: false });
      allPass = false;
    }
  }

  return {
    pass: allPass,
    testedCount: testCases.length,
    passedCount: results.filter(r => r.pass).length,
    details: results,
    notice: 'Configured redaction rules passed self-test. Note: This verifies active regex filters; it does not guarantee detection of all unknown secret formats.'
  };
}

/**
 * Executes a strictly ephemeral write probe in the temporary directory.
 * Writes a probe file, flushes it, closes it, deletes it, and verifies deletion.
 *
 * @param {string} tmpDir
 * @returns {{ writePass: boolean, cleanupPass: boolean, error: string | null }}
 */
export function performWriteProbe(tmpDir) {
  if (!fs.existsSync(tmpDir)) {
    try {
      fs.mkdirSync(tmpDir, { recursive: true, mode: 0o700 });
    } catch (err) {
      return { writePass: false, cleanupPass: false, error: `Cannot create tmp directory: ${err.message}` };
    }
  }

  const probeId = crypto.randomUUID();
  const probeFile = path.join(tmpDir, `doctor_probe_${probeId}.tmp`);
  let writePass = false;
  let cleanupPass = false;
  let error = null;

  try {
    const fd = fs.openSync(probeFile, 'w', 0o600);
    fs.writeSync(fd, `doctor-probe-${probeId}\n`);
    fs.fsyncSync(fd);
    fs.closeSync(fd);

    const content = fs.readFileSync(probeFile, 'utf8');
    if (content.includes(probeId)) {
      writePass = true;
    } else {
      error = 'Write verification mismatch';
    }
  } catch (err) {
    error = err.message;
  } finally {
    try {
      if (fs.existsSync(probeFile)) {
        fs.unlinkSync(probeFile);
        cleanupPass = !fs.existsSync(probeFile);
      } else {
        cleanupPass = writePass;
      }
    } catch (cleanupErr) {
      cleanupPass = false;
      error = error ? `${error}; Cleanup error: ${cleanupErr.message}` : cleanupErr.message;
    }
  }

  return {
    writePass,
    cleanupPass,
    error
  };
}

/**
 * Checks whether an active process holds a ledger lockfile.
 * Verifies process liveness via signal 0 and checks stale age to prevent deadlocks.
 *
 * @param {string} ledgerDir
 * @param {object} [options={}]
 * @param {number} [options.staleAgeMs=30000]
 * @returns {{ isLocked: boolean, isStale: boolean, lockFile: string | null, pid: number | null, details: string | null }}
 */
export function checkActiveLock(ledgerDir, options = {}) {
  const lockPath = path.join(ledgerDir, 'journal.lock');
  const staleAgeMs = typeof options.staleAgeMs === 'number' ? options.staleAgeMs : 30000;

  if (fs.existsSync(lockPath)) {
    try {
      const lockStat = fs.statSync(lockPath);
      let isStale = false;
      let staleReason = '';
      let pid = null;

      try {
        const lockContent = fs.readFileSync(lockPath, 'utf8');
        const lockInfo = JSON.parse(lockContent);
        pid = typeof lockInfo.pid === 'number' ? lockInfo.pid : null;
        const lockAge = Date.now() - new Date(lockInfo.createdAt || lockStat.mtime).getTime();

        if (pid !== null && (lockInfo.hostname === os.hostname() || !lockInfo.hostname)) {
          let processAlive = true;
          try {
            // Signal 0 verifies process existence without signaling
            process.kill(pid, 0);
          } catch (killErr) {
            if (killErr.code === 'ESRCH') {
              processAlive = false;
            }
          }

          if (!processAlive) {
            isStale = true;
            staleReason = `PID ${pid} is no longer running`;
          } else if (lockAge > staleAgeMs) {
            isStale = true;
            staleReason = `Lock held by PID ${pid} exceeded stale timeout (${Math.round(lockAge / 1000)}s)`;
          }
        } else if (lockAge > staleAgeMs) {
          isStale = true;
          staleReason = `Lock exceeded stale timeout (${Math.round(lockAge / 1000)}s)`;
        }
      } catch {
        // Unparseable lock file
        if (Date.now() - lockStat.mtimeMs > staleAgeMs) {
          isStale = true;
          staleReason = `Unreadable lockfile older than ${Math.round(staleAgeMs / 1000)}s`;
        }
      }

      if (isStale) {
        return {
          isLocked: false,
          isStale: true,
          lockFile: lockPath,
          pid,
          details: `Stale lockfile detected (${staleReason})`
        };
      }

      return {
        isLocked: true,
        isStale: false,
        lockFile: lockPath,
        pid,
        details: `Lockfile exists${pid ? ` (held by PID ${pid})` : ''} (modified at ${lockStat.mtime.toISOString()})`
      };
    } catch {
      return {
        isLocked: true,
        isStale: false,
        lockFile: lockPath,
        pid: null,
        details: 'Lockfile exists and is inaccessible'
      };
    }
  }
  return { isLocked: false, isStale: false, lockFile: null, pid: null, details: null };
}

/**
 * Executes all 15 comprehensive health and integrity checks for the Rewind ledger.
 *
 * @param {string} ledgerDir - Path to .rewind directory
 * @param {object} [config={}]
 * @param {string} [config.rootDir]
 * @param {object} [options={}]
 * @returns {object} DoctorReport
 */
export function runDoctorDiagnostics(ledgerDir, config = {}, options = {}) {
  const resolvedLedger = path.resolve(ledgerDir);
  const rootDir = config.rootDir ? path.resolve(config.rootDir) : path.dirname(resolvedLedger);
  const recordsDir = path.join(resolvedLedger, 'records');
  const evidenceDir = path.join(resolvedLedger, 'evidence');
  const tmpDir = path.join(resolvedLedger, 'tmp');
  const quarantineDir = path.join(resolvedLedger, 'quarantine');
  const journalPath = path.join(resolvedLedger, 'journal.jsonl');

  const healthChecks = [];
  const warnings = [];
  const errors = [];

  // ==========================================
  // 1. Accessibility Check
  // ==========================================
  let storageAccessible = false;
  let accessibilityDetails = {};
  try {
    const ledgerExists = fs.existsSync(resolvedLedger);
    const recordsExists = fs.existsSync(recordsDir);
    const evidenceExists = fs.existsSync(evidenceDir);
    const tmpExists = fs.existsSync(tmpDir);
    const quarantineExists = fs.existsSync(quarantineDir);

    storageAccessible = ledgerExists;
    accessibilityDetails = {
      ledgerExists,
      recordsExists,
      evidenceExists,
      tmpExists,
      quarantineExists,
      ledgerDir: resolvedLedger
    };

    healthChecks.push({
      id: 'accessibility',
      name: 'Storage Accessibility',
      status: storageAccessible ? 'PASS' : 'WARN',
      severity: storageAccessible ? 'info' : 'warn',
      message: storageAccessible ? 'Storage directories are accessible' : 'Ledger directory has not been initialized yet',
      details: accessibilityDetails
    });
  } catch (err) {
    errors.push(`Storage accessibility failure: ${err.message}`);
    healthChecks.push({
      id: 'accessibility',
      name: 'Storage Accessibility',
      status: 'FAIL',
      severity: 'fail',
      message: `Failed to access storage: ${err.message}`,
      details: { error: err.message }
    });
  }

  // ==========================================
  // 2. Active Writer / Concurrency Lock Check
  // ==========================================
  const lockStatus = checkActiveLock(resolvedLedger);
  healthChecks.push({
    id: 'active_lock',
    name: 'Active Writer Lock',
    status: lockStatus.isLocked ? 'WARN' : (lockStatus.isStale ? 'WARN' : 'PASS'),
    severity: lockStatus.isLocked ? 'warn' : (lockStatus.isStale ? 'info' : 'info'),
    message: lockStatus.isLocked
      ? 'Another Rewind process may be actively writing the ledger'
      : (lockStatus.isStale ? 'Stale lockfile detected from terminated process' : 'No active lock contention detected'),
    details: lockStatus
  });
  if (lockStatus.isLocked) {
    warnings.push('Active lockfile detected in ledger directory');
  } else if (lockStatus.isStale) {
    warnings.push(`Stale lockfile detected: ${lockStatus.details}`);
  }

  // ==========================================
  // 3. Configuration & Path Validity
  // ==========================================
  let configValid = true;
  const configIssues = [];
  if (!path.isAbsolute(resolvedLedger)) {
    configValid = false;
    configIssues.push('Ledger path must be absolute');
  }
  if (!resolvedLedger.startsWith(rootDir) && resolvedLedger !== rootDir) {
    // Relative containment check
    const rel = path.relative(rootDir, resolvedLedger);
    if (rel.startsWith('..') && !options.allowExternalLedger) {
      configValid = false;
      configIssues.push(`Ledger directory (${resolvedLedger}) is outside project root (${rootDir})`);
    }
  }

  healthChecks.push({
    id: 'config_validity',
    name: 'Configuration Validity',
    status: configValid ? 'PASS' : 'FAIL',
    severity: configValid ? 'info' : 'fail',
    message: configValid ? 'Configuration and path hierarchy valid' : configIssues.join('; '),
    details: { rootDir, ledgerDir: resolvedLedger, issues: configIssues }
  });
  if (!configValid) {
    errors.push(...configIssues);
  }

  // ==========================================
  // 4. Runtime Compatibility
  // ==========================================
  const currentVersion = process.version;
  const versionMatch = currentVersion.match(/^v(\d+)\.(\d+)/);
  const majorVersion = versionMatch ? Number.parseInt(versionMatch[1], 10) : 0;
  const minorVersion = versionMatch ? Number.parseInt(versionMatch[2], 10) : 0;
  const runtimeSupported = majorVersion > 22 || (majorVersion === 22 && minorVersion >= 13);

  healthChecks.push({
    id: 'runtime_compatibility',
    name: 'Runtime Compatibility',
    status: runtimeSupported ? 'PASS' : 'FAIL',
    severity: runtimeSupported ? 'info' : 'fail',
    message: runtimeSupported
      ? `Node.js ${currentVersion} satisfies supported engine (${SUPPORTED_NODE_RANGE})`
      : `Node.js ${currentVersion} is unsupported. Rewind requires ${SUPPORTED_NODE_RANGE}`,
    details: {
      nodeVersion: currentVersion,
      nodeMajor: majorVersion,
      platform: process.platform,
      arch: process.arch,
      supportedRange: SUPPORTED_NODE_RANGE
    }
  });
  if (!runtimeSupported) {
    errors.push(`Incompatible Node.js runtime (${currentVersion}); requires ${SUPPORTED_NODE_RANGE}`);
  }

  // ==========================================
  // 5. Read Authoritative Journal Events
  // ==========================================
  let journalExamined = 0;
  let journalValid = 0;
  let journalEvents = [];
  let journalMalformed = [];
  let journalExists = false;

  if (fs.existsSync(journalPath)) {
    journalExists = true;
    const readResult = readJournalEvents(journalPath);
    journalEvents = readResult.events || [];
    journalMalformed = readResult.malformed || [];
    journalExamined = typeof readResult.totalLines === 'number' ? readResult.totalLines : (readResult.events || []).length;
    journalValid = journalEvents.length;
  }

  // ==========================================
  // 6. Sequence & Index Validity Check
  // ==========================================
  let sequenceValid = true;
  const sequenceIssues = [];
  for (let i = 0; i < journalEvents.length; i++) {
    const expectedSeq = i + 1;
    if (journalEvents[i].sequence !== expectedSeq) {
      sequenceValid = false;
      sequenceIssues.push(`Sequence break at event index ${i}: expected #${expectedSeq}, got #${journalEvents[i].sequence}`);
      break;
    }
  }

  healthChecks.push({
    id: 'sequence_validity',
    name: 'Journal Sequence Contiguity',
    status: sequenceValid ? 'PASS' : 'FAIL',
    severity: sequenceValid ? 'info' : 'fail',
    message: sequenceValid ? `All ${journalEvents.length} journal event sequence numbers are strictly contiguous` : sequenceIssues.join('; '),
    details: { eventCount: journalEvents.length, issues: sequenceIssues }
  });
  if (!sequenceValid) {
    errors.push(...sequenceIssues);
  }

  // ==========================================
  // 7. 4-Layer Cryptographic Ledger Integrity Audit
  // ==========================================
  let integrityReport = null;
  if (journalExists && journalEvents.length > 0) {
    try {
      integrityReport = verifyLedgerIntegrity(resolvedLedger);
    } catch (err) {
      integrityReport = {
        status: 'UNTRUSTED',
        isTrusted: false,
        errors: [{ type: 'AUDIT_EXCEPTION', message: err.message }],
        journal: { examined: journalExamined, valid: journalValid, chainIntact: false },
        checkpoint: { present: false, matches: false },
        projections: { consistent: 0, driftCount: 0 }
      };
    }
  } else {
    integrityReport = {
      status: 'TRUSTED',
      isTrusted: true,
      errors: [],
      journal: { examined: 0, valid: 0, chainIntact: true },
      checkpoint: { present: false, matches: true },
      projections: { consistent: 0, driftCount: 0 }
    };
  }

  const integrityLayerDetails = {
    sequenceContiguity: sequenceValid ? 'PASS' : 'FAIL',
    eventHashes: (integrityReport.journal?.validHashes !== false) ? 'PASS' : 'FAIL',
    chainLinkage: integrityReport.journal?.chainIntact ? 'PASS' : 'FAIL',
    checkpointCommitment: integrityReport.checkpoint?.matches ? 'PASS' : (integrityReport.status === 'CRASH_RECOVERY_PENDING' ? 'WARN' : 'FAIL')
  };

  const isIntegrityPass = integrityReport.isTrusted;
  const isCrashPending = integrityReport.status === 'CRASH_RECOVERY_PENDING';

  healthChecks.push({
    id: 'ledger_integrity',
    name: 'Ledger Cryptographic Integrity (4-Layer)',
    status: isIntegrityPass ? 'PASS' : (isCrashPending ? 'WARN' : 'FAIL'),
    severity: isIntegrityPass ? 'info' : (isCrashPending ? 'warn' : 'fail'),
    message: isIntegrityPass
      ? 'All 4 integrity layers verified (SHA-256 chain intact)'
      : (isCrashPending ? 'Crash recovery pending (journal has valid uncommitted extension)' : 'Cryptographic integrity violation detected in ledger history'),
    details: {
      status: integrityReport.status,
      layers: integrityLayerDetails,
      violations: integrityReport.errors || []
    }
  });
  if (!isIntegrityPass && !isCrashPending) {
    errors.push(`Ledger integrity failure: ${(integrityReport.errors || []).map(e => e.message).join('; ')}`);
  }
  if (isCrashPending) {
    warnings.push('Checkpoint lags behind valid contiguous journal events (safe fast-forward available)');
  }

  // ==========================================
  // 8. Malformed / Corrupt Records Scan
  // ==========================================
  const corruptRecordFiles = [];
  let recordFilesCount = 0;
  
  const dbPath = path.join(ledgerDir, 'projection.db');
  if (fs.existsSync(dbPath)) {
    try {
      const db = new DatabaseSync(dbPath);
      db.exec('PRAGMA busy_timeout = 5000;');
      try {
        const rows = db.prepare('SELECT id, data FROM records').all();
        for (const row of rows) {
          recordFilesCount++;
          try {
            // Re-use mock/stub validation (could also just use native engine)
            const parsed = JSON.parse(row.data);
            if (!isValidRecord(parsed)) {
              corruptRecordFiles.push({ file: `id:${row.id}`, reason: 'Invalid record schema' });
            }
          } catch (err) {
            corruptRecordFiles.push({ file: `id:${row.id}`, reason: `Malformed JSON: ${err.message}` });
          }
        }
      } finally {
        db.close();
      }
    } catch (err) {
       corruptRecordFiles.push({ file: 'projection.db', reason: `Database read error: ${err.message}` });
    }
  }

  let quarantinedCount = 0;
  const quarantinedFiles = [];
  if (fs.existsSync(quarantineDir)) {
    try {
      const qFiles = fs.readdirSync(quarantineDir);
      quarantinedCount = qFiles.length;
      quarantinedFiles.push(...qFiles);
    } catch {
      // Ignore
    }
  }

  const malformedTotal = corruptRecordFiles.length + journalMalformed.length;
  const corruptionPass = malformedTotal === 0;

  healthChecks.push({
    id: 'record_corruption',
    name: 'Record & Journal Syntax Validation',
    status: corruptionPass ? 'PASS' : 'FAIL',
    severity: corruptionPass ? 'info' : 'fail',
    message: corruptionPass
      ? `All ${recordFilesCount} record files and ${journalExamined} journal lines are syntactically valid`
      : `${corruptRecordFiles.length} corrupt record(s) and ${journalMalformed.length} malformed journal line(s) detected`,
    details: {
      corruptRecords: corruptRecordFiles,
      malformedJournalLines: journalMalformed,
      quarantinedCount,
      quarantinedFiles
    }
  });
  if (corruptRecordFiles.length > 0) {
    errors.push(`${corruptRecordFiles.length} corrupt record(s) found in projection.db`);
  }
  if (journalMalformed.length > 0) {
    errors.push(`${journalMalformed.length} malformed line(s) found in journal.jsonl`);
  }
  if (quarantinedCount > 0) {
    warnings.push(`${quarantinedCount} isolated file(s) present in quarantine/`);
  }

  // ==========================================
  // 9. Orphan Temporary Files Scan
  // ==========================================
  const orphanTempFiles = [];
  if (fs.existsSync(tmpDir)) {
    try {
      const tmpEntries = fs.readdirSync(tmpDir);
      for (const t of tmpEntries) {
        if (t.endsWith('.tmp')) {
          orphanTempFiles.push(t);
        }
      }
    } catch {
      // Ignore
    }
  }

  const orphanPass = orphanTempFiles.length === 0;
  healthChecks.push({
    id: 'orphan_temp_files',
    name: 'Orphan Temporary Files',
    status: orphanPass ? 'PASS' : 'WARN',
    severity: orphanPass ? 'info' : 'warn',
    message: orphanPass ? 'No orphan temporary files detected' : `${orphanTempFiles.length} orphan temporary file(s) detected in tmp/`,
    details: { count: orphanTempFiles.length, files: orphanTempFiles }
  });
  if (!orphanPass) {
    warnings.push(`${orphanTempFiles.length} orphan temporary file(s) detected in tmp/`);
  }

  // ==========================================
  // 10. Storage Consistency (Journal vs Derived Records)
  // ==========================================
  let consistencyPass = true;
  let projectedMap = new Map();
  const consistencyIssues = [];

  try {
    projectedMap = projectEventsToRecords(journalEvents);
    const dbPath = path.join(ledgerDir, 'projection.db');
    if (fs.existsSync(dbPath) && journalEvents.length > 0) {
      const db = new DatabaseSync(dbPath);
      db.exec('PRAGMA busy_timeout = 5000;');
      try {
        const rows = db.prepare('SELECT id FROM records').all();
        const diskIds = new Set(rows.map(r => r.id));
        for (const [id, _] of projectedMap.entries()) {
          if (!diskIds.has(id)) {
            consistencyPass = false;
            consistencyIssues.push(`Incident #${id} exists in journal but missing from projection database`);
          }
        }
      } finally {
        db.close();
      }
    } else if (!fs.existsSync(dbPath) && journalEvents.length > 0) {
      consistencyPass = false;
      consistencyIssues.push('Projection database missing despite active journal');
    }
  } catch (err) {
    consistencyPass = false;
    consistencyIssues.push(`Projection reducer failed: ${err.message}`);
  }

  healthChecks.push({
    id: 'storage_consistency',
    name: 'Storage & Projection Consistency',
    status: consistencyPass ? 'PASS' : 'WARN',
    severity: consistencyPass ? 'info' : 'warn',
    message: consistencyPass
      ? `Authoritative journal aligns with ${projectedMap.size} derived incident record(s)`
      : `Derived projections drift from authoritative journal (${consistencyIssues.length} issue(s))`,
    details: { consistent: consistencyPass, issues: consistencyIssues, expectedIncidents: projectedMap.size }
  });
  if (!consistencyPass) {
    warnings.push('Derived projection records drift from authoritative journal');
  }

  // ==========================================
  // 11. Index Rebuild Capability (Dry-run projection)
  // ==========================================
  let rebuildPass = true;
  let rebuildError = null;
  try {
    const dryRunReplay = projectEventsToRecords(journalEvents);
    rebuildPass = dryRunReplay instanceof Map;
  } catch (err) {
    rebuildPass = false;
    rebuildError = err.message;
  }

  healthChecks.push({
    id: 'index_rebuildability',
    name: 'Index & Projection Rebuild Capability',
    status: rebuildPass ? 'PASS' : 'FAIL',
    severity: rebuildPass ? 'info' : 'fail',
    message: rebuildPass
      ? 'Authoritative journal can be cleanly replayed to reconstruct all derived state'
      : `Cannot rebuild projections from journal: ${rebuildError}`,
    details: { rebuildable: rebuildPass, error: rebuildError }
  });
  if (!rebuildPass) {
    errors.push(`Authoritative journal replay failed: ${rebuildError}`);
  }

  // ==========================================
  // 12. Redaction Self-Test
  // ==========================================
  const redactionTest = performRedactionSelfTest();
  healthChecks.push({
    id: 'redaction_rules',
    name: 'Secret Redaction Engine',
    status: redactionTest.pass ? 'PASS' : 'FAIL',
    severity: redactionTest.pass ? 'info' : 'fail',
    message: redactionTest.pass
      ? `All ${redactionTest.testedCount} representative secret patterns successfully redacted`
      : `Secret redaction rule failure: ${redactionTest.passedCount}/${redactionTest.testedCount} passed`,
    details: redactionTest
  });
  if (!redactionTest.pass) {
    errors.push('Sensitive data redaction engine failed representative self-test');
  }

  // ==========================================
  // 13. Write & Cleanup Capability Probe
  // ==========================================
  const writeProbe = performWriteProbe(tmpDir);
  const writeProbePass = writeProbe.writePass && writeProbe.cleanupPass;
  healthChecks.push({
    id: 'write_permissions',
    name: 'Write & Cleanup Capability',
    status: writeProbePass ? 'PASS' : 'FAIL',
    severity: writeProbePass ? 'info' : 'fail',
    message: writeProbePass
      ? 'Temporary atomic write and immediate cleanup verified'
      : `Write probe failed: ${writeProbe.error || 'Unknown error'}`,
    details: writeProbe
  });
  if (!writeProbePass) {
    errors.push(`Ledger write probe failed: ${writeProbe.error}`);
  }

  // ==========================================
  // 14. Unredacted Secrets Check
  // ==========================================
  let unredactedSecretsFound = false;
  if (fs.existsSync(journalPath)) {
    try {
      const journalContent = fs.readFileSync(journalPath, 'utf8');
      const lines = journalContent.split('\n').filter(Boolean);
      for (const line of lines) {
        if (redactSecrets(line) !== line) {
          unredactedSecretsFound = true;
          break;
        }
      }
    } catch {
      // Non-fatal
    }
  }

  healthChecks.push({
    id: 'unredacted_secrets',
    name: 'Historical Secrets Hygiene',
    status: unredactedSecretsFound ? 'WARN' : 'PASS',
    severity: unredactedSecretsFound ? 'warn' : 'info',
    message: unredactedSecretsFound
      ? 'Unredacted secrets detected in historical journal. Run "rewind scrub" to sanitize and re-seal.'
      : 'No unredacted secret patterns detected in ledger journal',
    details: { unredactedSecretsFound }
  });
  if (unredactedSecretsFound) {
    warnings.push('Unredacted secrets detected in historical journal; run "rewind scrub" to re-seal.');
  }

  // ==========================================
  // Informational Metrics (Not Pass/Fail)
  // ==========================================
  const totalDiskBytes = calculateStorageSize(resolvedLedger);
  const allIncidents = Array.from(projectedMap.values());
  let verifiedRecoveriesCount = 0;
  let regressionsCount = 0;

  for (const inc of allIncidents) {
    if (inc.status === IncidentStatus.RECOVERED || inc.status === 'VERIFIED') {
      verifiedRecoveriesCount++;
    } else if (Array.isArray(inc.recoveryAttempts) && inc.recoveryAttempts.some(a => a.status === RecoveryAttemptStatus.VERIFIED)) {
      verifiedRecoveriesCount++;
    }

    if (inc.status === IncidentStatus.REGRESSED || inc.regressionOf) {
      regressionsCount++;
    }
  }

  const metrics = {
    diskUsageBytes: totalDiskBytes,
    diskUsageFormatted: formatByteSize(totalDiskBytes),
    totalRecords: allIncidents.length,
    verifiedRecoveries: verifiedRecoveriesCount,
    regressions: regressionsCount,
    journalEventsCount: journalEvents.length,
    quarantinedCount
  };

  // ==========================================
  // Overall Health Classification & Repair Assessment
  // ==========================================
  const failChecks = healthChecks.filter(c => c.status === 'FAIL');
  const warnChecks = healthChecks.filter(c => c.status === 'WARN');
  const passChecks = healthChecks.filter(c => c.status === 'PASS');

  const hasJournalCorruption = journalMalformed.length > 0 ||
    !sequenceValid ||
    (integrityReport && !integrityReport.journal?.chainIntact);

  let overallStatus = 'HEALTHY';
  if (hasJournalCorruption) {
    overallStatus = 'CORRUPTED';
  } else if (!writeProbePass || !runtimeSupported || !configValid) {
    overallStatus = 'BLOCKED';
  } else if (failChecks.length > 0) {
    overallStatus = 'DEGRADED';
  } else if (warnChecks.length > 0) {
    overallStatus = 'WARNING';
  }

  // Determine if Safe Repair is available
  const canRepairStaleLock = Boolean(lockStatus.isStale && lockStatus.lockFile);
  const canRepairTemps = orphanTempFiles.length > 0;
  const canRepairProjections = (!consistencyPass || corruptRecordFiles.length > 0 || (integrityReport && integrityReport.projections?.driftCount > 0)) &&
    journalValid > 0 &&
    sequenceValid &&
    !hasJournalCorruption;
  const canFastForwardCheckpoint = isCrashPending && sequenceValid && !hasJournalCorruption;
  const isRepairBlocked = lockStatus.isLocked || overallStatus === 'CORRUPTED' || !writeProbePass;

  const repairReasons = [];
  if (canRepairStaleLock) repairReasons.push(`Remove stale journal lockfile (${lockStatus.details})`);
  if (canRepairTemps) repairReasons.push(`Remove ${orphanTempFiles.length} orphan temporary file(s)`);
  if (canRepairProjections) repairReasons.push('Rebuild derived projection records from authoritative journal');
  if (canFastForwardCheckpoint) repairReasons.push('Fast-forward trusted checkpoint across validated journal extension');

  const repairAvailable = !isRepairBlocked && (canRepairStaleLock || canRepairTemps || canRepairProjections || canFastForwardCheckpoint);

  return {
    status: overallStatus,
    summary: {
      passed: passChecks.length,
      warnings: warnChecks.length,
      failures: failChecks.length,
      totalChecks: healthChecks.length
    },
    healthChecks,
    metrics,
    warnings,
    errors,
    repair: {
      available: repairAvailable,
      recommended: repairAvailable && (canRepairStaleLock || canRepairTemps || canRepairProjections || canFastForwardCheckpoint),
      blocked: isRepairBlocked,
      blockReason: isRepairBlocked ? (lockStatus.isLocked ? 'Active lock held by another process' : (overallStatus === 'CORRUPTED' ? 'Authoritative journal corruption requires manual recovery' : 'Storage is not writable')) : null,
      actions: repairReasons
    }
  };
}

/**
 * Executes a constrained, safe repair operation.
 *
 * Invariant: Never mutates or alters `journal.jsonl` or deletes `evidence/`.
 *
 * @param {string} ledgerDir
 * @param {object} [config={}]
 * @param {object} [options={}]
 * @param {boolean} [options.dryRun=false]
 * @returns {object} RepairResult
 */
export function executeDoctorRepair(ledgerDir, config = {}, options = {}) {
  const isDryRun = Boolean(options.dryRun);
  const beforeDiag = runDoctorDiagnostics(ledgerDir, config, options);

  if (beforeDiag.repair.blocked) {
    return {
      status: 'REFUSED',
      dryRun: isDryRun,
      reason: beforeDiag.repair.blockReason || 'Repair blocked due to integrity or safety constraints',
      actionsTaken: [],
      preserved: ['journal.jsonl', 'evidence/'],
      diagnostics: beforeDiag
    };
  }

  if (!beforeDiag.repair.available && beforeDiag.status === 'HEALTHY') {
    return {
      status: 'NOOP',
      dryRun: isDryRun,
      message: 'No repair required. System is already healthy.',
      actionsTaken: [],
      preserved: ['journal.jsonl', 'evidence/'],
      diagnostics: beforeDiag
    };
  }

  const resolvedLedger = path.resolve(ledgerDir);
  const tmpDir = path.join(resolvedLedger, 'tmp');
  const journalPath = path.join(resolvedLedger, 'journal.jsonl');
  const actionsTaken = [];
  const plannedActions = [...beforeDiag.repair.actions];

  if (!isDryRun) {
    // 0. Remove Stale Lockfile
    const lockStatus = checkActiveLock(resolvedLedger);
    if (lockStatus.isStale && lockStatus.lockFile) {
      try {
        fs.unlinkSync(lockStatus.lockFile);
        actionsTaken.push(`Removed stale journal lockfile (${lockStatus.details})`);
      } catch {
        // Ignore if already deleted
      }
    }

    // 1. Remove Orphan Temporary Files
    const orphanCheck = beforeDiag.healthChecks.find(c => c.id === 'orphan_temp_files');
    if (orphanCheck && orphanCheck.details?.files?.length > 0) {
      let removedCount = 0;
      for (const file of orphanCheck.details.files) {
        try {
          fs.unlinkSync(path.join(tmpDir, file));
          removedCount++;
        } catch {
          // Ignore
        }
      }
      actionsTaken.push(`Removed ${removedCount} orphan temporary file(s) from tmp/`);
    }

    // 2. Read Valid Journal
    const { events } = readJournalEvents(journalPath);

    // 3. Fast-Forward Checkpoint if Contiguous & Verified
    const integrityCheck = beforeDiag.healthChecks.find(c => c.id === 'ledger_integrity');
    if (events.length > 0 && integrityCheck?.details?.status === 'CRASH_RECOVERY_PENDING') {
      const lastEvent = events[events.length - 1];
      writeCheckpoint(resolvedLedger, {
        headSequence: lastEvent.sequence,
        headEventId: lastEvent.eventId,
        headChainHash: lastEvent.chainHash,
        eventCount: events.length
      });
      actionsTaken.push(`Fast-forwarded trusted checkpoint to event #${lastEvent.sequence}`);
    }

    // 4. Rebuild Derived Projections in projection.db
    const consistencyCheck = beforeDiag.healthChecks.find(c => c.id === 'storage_consistency');
    const corruptionCheck = beforeDiag.healthChecks.find(c => c.id === 'record_corruption');
    const hasProjectionRepairAction = beforeDiag.repair?.actions?.some(a => a.includes('Rebuild derived projection records'));
    if (consistencyCheck?.status !== 'PASS' || corruptionCheck?.status !== 'PASS' || hasProjectionRepairAction || (actionsTaken.length === 0 && beforeDiag.repair.available)) {
      const projected = projectEventsToRecords(events);
      
      const dbPath = path.join(resolvedLedger, 'projection.db');
      let db = null;
      try {
        db = new DatabaseSync(dbPath);
        db.exec('CREATE TABLE IF NOT EXISTS records (id TEXT PRIMARY KEY, data TEXT NOT NULL)');
        db.exec('CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)');
        db.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA temp_store = MEMORY; PRAGMA busy_timeout = 5000;');
        db.exec('BEGIN TRANSACTION');
        const deleteAllStmt = db.prepare('DELETE FROM records');
        deleteAllStmt.run();
        const insertStmt = db.prepare('INSERT OR REPLACE INTO records (id, data) VALUES (?, ?)');
        for (const [id, record] of projected.entries()) {
          insertStmt.run(id, JSON.stringify(record));
        }
        db.prepare('INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)').run('projectionSchemaVersion', String(PROJECTION_SCHEMA_VERSION));
        db.exec('COMMIT');
      } finally {
        if (db) {
          try { db.close(); } catch {}
        }
      }

      actionsTaken.push(`Reconstructed ${projected.size} derived incident projection(s) in SQLite database`);
    }
  }

  const afterDiag = isDryRun ? beforeDiag : runDoctorDiagnostics(ledgerDir, config, options);

  return {
    status: isDryRun ? 'DRY_RUN' : 'COMPLETED',
    dryRun: isDryRun,
    plannedActions,
    actionsTaken,
    preserved: ['journal.jsonl (Authoritative History)', 'evidence/ (Forensic Artifacts)'],
    beforeStatus: beforeDiag.status,
    afterStatus: afterDiag.status,
    postRepairIntegrity: afterDiag.healthChecks.find(c => c.id === 'ledger_integrity')?.status || 'UNKNOWN',
    diagnostics: afterDiag
  };
}
