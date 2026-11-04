import crypto from 'node:crypto';
import { computeFingerprint, inferFingerprintVersion } from './fingerprint.js';
import { IncidentStatus, RecoveryAttemptStatus, ProvenanceType, EvidenceQuality } from './state.js';
import { parseDiagnostic } from '../diagnostics/index.js';
import { redactRecordForStorage } from '../sanitizer.js';

const MAX_OUTPUT_HEAD = 64 * 1024; // 64 KB
const MAX_OUTPUT_TAIL = 16 * 1024; // 16 KB

/**
 * Truncates large string output cleanly preserving head and tail,
 * and computing a deterministic SHA-256 hash of the complete text.
 *
 * @param {string} text
 * @returns {{ bounded: string, hash: string, truncated: boolean }}
 */
export function boundOutput(text) {
  if (!text || typeof text !== 'string') {
    return {
      bounded: '',
      hash: crypto.createHash('sha256').update('', 'utf8').digest('hex'),
      truncated: false
    };
  }

  const hash = crypto.createHash('sha256').update(text, 'utf8').digest('hex');

  if (text.length <= MAX_OUTPUT_HEAD + MAX_OUTPUT_TAIL) {
    return {
      bounded: text,
      hash,
      truncated: false
    };
  }

  const head = text.slice(0, MAX_OUTPUT_HEAD);
  const tail = text.slice(-MAX_OUTPUT_TAIL);
  const omittedCount = text.length - MAX_OUTPUT_HEAD - MAX_OUTPUT_TAIL;
  const bounded = `${head}\n... [${omittedCount} bytes omitted; full output SHA-256: ${hash}] ...\n${tail}`;

  return {
    bounded,
    hash,
    truncated: true
  };
}

/**
 * @typedef {object} VerificationRun
 * @property {number} id - Run number: 1, 2...
 * @property {string} startedAt - ISO timestamp
 * @property {string} completedAt - ISO timestamp
 * @property {string} command - Verification command
 * @property {number} exitCode - Exit code
 * @property {number} durationMs - Duration in ms
 * @property {string} output - Output snippet
 * @property {string} outputHash - Complete output hash
 * @property {string} environmentFingerprint - Hash of environment at time of run
 * @property {'PASSED'|'FAILED'} result - Verification outcome
 */

/**
 * @typedef {object} RecoveryAttempt
 * @property {number} id - Attempt ID: 1, 2, 3...
 * @property {string} createdAt - ISO timestamp
 * @property {string|null} cause - Root cause hypothesis
 * @property {string|null} change - Remediation description
 * @property {string|null} verifyCmd - Verification command
 * @property {string} status - PROPOSED | ATTEMPTED | FAILED | VERIFIED
 * @property {VerificationRun[]} verificationRuns - Complete history of verification runs
 */

/**
 * @typedef {object} IncidentRecord
 * @property {string} id - Monotonically increasing unique record ID (e.g. "1")
 * @property {string} fingerprint - Deterministic failure hash (64 hex chars for v2, 16 hex chars for legacy v1)
 * @property {number} [fingerprintVersion=2] - Fingerprint schema version (1 = legacy 16-hex, 2 = full 64-hex SHA-256)
 * @property {string} status - OBSERVED | OPEN | RECOVERED | REGRESSED | RESOLVED | success
 * @property {string} command - Target command executable
 * @property {string[]} args - Target command arguments
 * @property {string} fullCommand - Full command string
 * @property {string} cwd - Working directory
 * @property {string} startTime - ISO start timestamp
 * @property {string} endTime - ISO end timestamp
 * @property {number} durationMs - Duration in milliseconds
 * @property {number|null} exitCode - Exit code
 * @property {string|null} signal - Termination signal
 * @property {string} stdout - Sanitized bounded stdout
 * @property {string} stderr - Sanitized bounded stderr
 * @property {string} evidenceHash - SHA-256 of complete raw output
 * @property {string} normalizedError - Normalized error signature
 * @property {import('../git.js').GitMetadata} git - Git metadata
 * @property {import('../environment.js').EnvironmentSnapshot} environment - Environment snapshot
 * @property {string|null} regressionOf - Prior verified incident ID if REGRESSED
 * @property {RecoveryAttempt[]} recoveryAttempts - Chronological remediation attempts
 * @property {Array<{ timestamp: string, cause?: string, change?: string, verifyCmd?: string }>} [recoveries] - Legacy compat alias
 * @property {object|null} [verification] - Legacy compat alias
 */

/**
 * Creates a structured IncidentRecord from a command execution capture result.
 *
 * @param {string} id
 * @param {import('../capture.js').CaptureRecord} captureResult
 * @param {object} [options]
 * @param {string} [options.initialState]
 * @param {string|null} [options.regressionOf]
 * @returns {IncidentRecord}
 */
export function createRecord(id, captureResult, options = {}) {
  const { fingerprint, fingerprintVersion, normalizedError } = computeFingerprint({
    command: captureResult.command,
    args: captureResult.args,
    exitCode: captureResult.exitCode,
    signal: captureResult.signal,
    stderr: captureResult.stderr,
    stdout: captureResult.stdout
  });

  const boundedStdout = boundOutput(captureResult.stdout || '');
  const boundedStderr = boundOutput(captureResult.stderr || '');

  // Combined evidence hash
  const rawCombined = `${captureResult.stdoutRaw || captureResult.stdout || ''}\n${captureResult.stderrRaw || captureResult.stderr || ''}`;
  const evidenceHash = crypto.createHash('sha256').update(rawCombined, 'utf8').digest('hex');

  const status = options.initialState || (captureResult.success ? 'success' : IncidentStatus.OBSERVED);

  const effectiveFingerprint = captureResult.fingerprint || fingerprint;
  const effectiveFingerprintVersion = inferFingerprintVersion(
    effectiveFingerprint,
    captureResult.fingerprintVersion || fingerprintVersion
  );

  const baseRecord = {
    id: String(id),
    fingerprint: effectiveFingerprint,
    fingerprintVersion: effectiveFingerprintVersion,
    status,
    command: captureResult.command,
    args: [...(captureResult.args || [])],
    fullCommand: captureResult.fullCommand,
    cwd: captureResult.cwd,
    startTime: captureResult.startTime,
    endTime: captureResult.endTime,
    durationMs: captureResult.durationMs,
    exitCode: captureResult.exitCode,
    signal: captureResult.signal,
    stdout: boundedStdout.bounded,
    stderr: boundedStderr.bounded,
    stdoutRaw: captureResult.stdoutRaw,
    stderrRaw: captureResult.stderrRaw,
    evidenceHash,
    normalizedError,
    diagnostic: captureResult.diagnostic || parseDiagnostic(captureResult.stderrRaw || captureResult.stderr, captureResult.stdoutRaw || captureResult.stdout, { command: captureResult.command, cwd: captureResult.cwd }),
    git: { ...captureResult.git },
    environment: { ...captureResult.environment },
    regressionOf: options.regressionOf || null,
    recoveryAttempts: [],
    // Legacy compatibility fields
    recoveries: [],
    verification: null
  };

  return Object.freeze(redactRecordForStorage(baseRecord));
}

/**
 * Migrates a record loaded from disk to the current schema if necessary.
 *
 * @param {Record<string, any>} record
 * @returns {IncidentRecord}
 */
export function normalizeRecordToCurrentSchema(record) {
  if (!record || typeof record !== 'object') return record;

  const copy = { ...record };

  // Ensure diagnostic is present (parse legacy records on the fly if missing)
  if (copy.diagnostic === undefined) {
    copy.diagnostic = parseDiagnostic(copy.stderrRaw || copy.stderr, copy.stdoutRaw || copy.stdout, { command: copy.command, cwd: copy.cwd });
  }

  // Ensure recoveryAttempts is present
  if (!Array.isArray(copy.recoveryAttempts)) {
    copy.recoveryAttempts = [];

    // Migrate legacy recoveries array if present
    if (Array.isArray(copy.recoveries) && copy.recoveries.length > 0) {
      for (let i = 0; i < copy.recoveries.length; i++) {
        const legacy = copy.recoveries[i];
        const isLast = i === copy.recoveries.length - 1;
        const runs = [];

        let attemptStatus = RecoveryAttemptStatus.PROPOSED;
        if (isLast && copy.verification) {
          const runPassed = copy.verification.exitCode === 0;
          attemptStatus = runPassed ? RecoveryAttemptStatus.VERIFIED : RecoveryAttemptStatus.FAILED;

          runs.push({
            id: 1,
            startedAt: copy.verification.verifiedAt || copy.verification.lastAttemptAt || legacy.timestamp || copy.startTime,
            completedAt: copy.verification.verifiedAt || copy.verification.lastAttemptAt || legacy.timestamp || copy.endTime,
            command: copy.verification.command || legacy.verifyCmd || '',
            exitCode: copy.verification.exitCode ?? (runPassed ? 0 : 1),
            durationMs: copy.verification.durationMs || 0,
            output: copy.verification.output || '',
            outputHash: crypto.createHash('sha256').update(copy.verification.output || '', 'utf8').digest('hex'),
            environmentFingerprint: copy.environment?.fingerprint || '',
            result: runPassed ? 'PASSED' : 'FAILED',
            provenance: ProvenanceType.DIRECTLY_VERIFIED
          });
        }

        copy.recoveryAttempts.push({
          id: i + 1,
          createdAt: legacy.timestamp || copy.startTime,
          cause: legacy.cause || null,
          causeProvenance: legacy.cause ? ProvenanceType.USER_REPORTED : null,
          change: legacy.change || null,
          changeProvenance: legacy.change ? ProvenanceType.USER_REPORTED : null,
          verifyCmd: legacy.verifyCmd || null,
          verifyCmdProvenance: legacy.verifyCmd ? ProvenanceType.USER_REPORTED : null,
          observedChanges: null,
          status: attemptStatus,
          evidenceQuality: attemptStatus === RecoveryAttemptStatus.VERIFIED ? EvidenceQuality.DIRECT : EvidenceQuality.USER_REPORTED,
          verificationRuns: runs
        });
      }
    }
  }

  // Normalize provenance and evidence quality on all attempts
  copy.recoveryAttempts = copy.recoveryAttempts.map((attempt) => {
    const runs = (Array.isArray(attempt.verificationRuns) ? attempt.verificationRuns : []).map((r) => ({
      ...r,
      provenance: r.provenance || ProvenanceType.DIRECTLY_VERIFIED
    }));

    let quality = attempt.evidenceQuality;
    if (!quality) {
      if (attempt.status === RecoveryAttemptStatus.VERIFIED) {
        quality = EvidenceQuality.DIRECT;
      } else if (attempt.status === RecoveryAttemptStatus.FIXED || attempt.status === RecoveryAttemptStatus.PROPOSED) {
        quality = EvidenceQuality.UNVERIFIED;
      } else if (attempt.change || attempt.cause) {
        quality = EvidenceQuality.USER_REPORTED;
      } else {
        quality = EvidenceQuality.UNVERIFIED;
      }
    }

    return {
      ...attempt,
      causeProvenance: attempt.causeProvenance || (attempt.cause ? ProvenanceType.USER_REPORTED : null),
      changeProvenance: attempt.changeProvenance || (attempt.change ? ProvenanceType.USER_REPORTED : null),
      verifyCmdProvenance: attempt.verifyCmdProvenance || (attempt.verifyCmd ? ProvenanceType.USER_REPORTED : null),
      observedChanges: attempt.observedChanges || null,
      status: attempt.status || RecoveryAttemptStatus.PROPOSED,
      isExternal: Boolean(attempt.isExternal),
      externalVerification: attempt.externalVerification || null,
      evidenceQuality: quality,
      verificationRuns: runs
    };
  });

  // Normalize fingerprint version using centralized inference
  copy.fingerprintVersion = inferFingerprintVersion(copy.fingerprint, copy.fingerprintVersion);

  // Normalize legacy status string
  if (copy.status === 'FIXED' || copy.status === 'SUSPECTED') {
    copy.status = IncidentStatus.OPEN;
  } else if (copy.status === 'VERIFIED') {
    copy.status = IncidentStatus.RECOVERED;
  }

  // Keep legacy compat properties in sync
  copy.recoveries = copy.recoveryAttempts.map(a => ({
    timestamp: a.createdAt,
    cause: a.cause,
    change: a.change,
    verifyCmd: a.verifyCmd
  }));

  // Find latest verification if any
  let latestRun = null;
  for (const attempt of copy.recoveryAttempts) {
    if (Array.isArray(attempt.verificationRuns)) {
      for (const run of attempt.verificationRuns) {
        if (!latestRun || run.startedAt > latestRun.startedAt) {
          latestRun = run;
        }
      }
    }
  }

  if (latestRun) {
    copy.verification = {
      verifiedAt: latestRun.result === 'PASSED' ? latestRun.completedAt : null,
      lastAttemptAt: latestRun.result === 'FAILED' ? latestRun.completedAt : null,
      command: latestRun.command || null,
      exitCode: typeof latestRun.exitCode === 'number' ? latestRun.exitCode : null,
      durationMs: typeof latestRun.durationMs === 'number' ? latestRun.durationMs : 0,
      output: latestRun.output || ''
    };
  } else {
    copy.verification = null;
  }

  return Object.freeze(copy);
}

/**
 * Validates whether an unparsed or parsed object conforms to the FailureRecord / IncidentRecord schema.
 *
 * @param {unknown} obj
 * @returns {boolean}
 */
export function isValidRecord(obj) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    return false;
  }

  const record = /** @type {Record<string, unknown>} */ (obj);

  if (
    typeof record.id !== 'string' ||
    record.id.trim() === '' ||
    typeof record.fingerprint !== 'string' ||
    typeof record.command !== 'string' ||
    !Array.isArray(record.args) ||
    typeof record.startTime !== 'string' ||
    (typeof record.exitCode !== 'number' && record.exitCode !== null) ||
    typeof record.status !== 'string' ||
    typeof record.stdout !== 'string' ||
    typeof record.stderr !== 'string'
  ) {
    return false;
  }

  // Strict version-to-length fingerprint validation:
  // v1 must be 16 hex characters; v2 must be 64 hex characters.
  const fp = record.fingerprint.trim();
  const version = record.fingerprintVersion;

  if (version === 1) {
    return /^[0-9a-f]{16}$/i.test(fp);
  }
  if (version === 2) {
    return /^[0-9a-f]{64}$/i.test(fp);
  }

  // If fingerprintVersion is omitted or not 1/2, must match either valid v1 or v2 format
  return /^[0-9a-f]{16}$/i.test(fp) || /^[0-9a-f]{64}$/i.test(fp);
}

