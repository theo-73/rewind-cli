import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  IncidentStatus,
  RecoveryAttemptStatus,
  ProvenanceType,
  EvidenceQuality,
  assertValidIncidentTransition,
  assertValidAttemptTransition
} from './state.js';
import { normalizeRecordToCurrentSchema } from './record.js';
import { inferFingerprintVersion } from './fingerprint.js';

export const PROJECTION_SCHEMA_VERSION = 1;

/**
 * Pure deterministic single-event reducer that applies a journal event to an incident Map in place.
 *
 * @param {Map<string, import('./record.js').IncidentRecord>} incidents - Active index map
 * @param {object} event - Journal event
 * @returns {import('./record.js').IncidentRecord|null} - The updated or created IncidentRecord, or null
 */
export function applyEventToRecordMap(incidents, event) {
  if (!event || !event.type || !event.incidentId) {
    return null;
  }

  const id = String(event.incidentId);

  switch (event.type) {
    case 'failure.observed': {
      const payload = event.payload || {};
      const newRecord = {
        id,
        fingerprint: payload.fingerprint || '',
        fingerprintVersion: inferFingerprintVersion(payload.fingerprint, payload.fingerprintVersion),
        command: payload.command || '',
        args: Array.isArray(payload.args) ? payload.args : [],
        fullCommand: payload.fullCommand || `${payload.command || ''} ${(payload.args || []).join(' ')}`.trim(),
        cwd: payload.cwd || '',
        startTime: payload.startTime || event.timestamp,
        endTime: payload.endTime || event.timestamp,
        durationMs: payload.durationMs || 0,
        exitCode: payload.exitCode ?? 1,
        signal: payload.signal || null,
        status: IncidentStatus.OBSERVED,
        stdout: payload.stdoutSnippet || payload.stdout || '',
        stderr: payload.stderrSnippet || payload.stderr || '',
        normalizedError: payload.normalizedError || '',
        evidenceHash: payload.evidenceHash || '',
        evidenceRef: payload.evidenceRef || '',
        diagnostic: payload.diagnostic || null,
        isTruncated: Boolean(payload.isTruncated),
        git: payload.git || { isGit: false },
        environment: payload.environment || {},
        regressionOf: null,
        recoveryAttempts: [],
        _projection: {
          notice: 'DERIVED AND REBUILDABLE. Authoritative source of truth is .rewind/journal.jsonl',
          projectionSchemaVersion: PROJECTION_SCHEMA_VERSION,
          derivedFromSequence: event.sequence,
          projectedAt: event.timestamp
        }
      };
      incidents.set(id, normalizeRecordToCurrentSchema(newRecord));
      break;
    }

    case 'regression.detected': {
      const payload = event.payload || {};
      const newRecord = {
        id,
        fingerprint: payload.fingerprint || '',
        fingerprintVersion: inferFingerprintVersion(payload.fingerprint, payload.fingerprintVersion),
        command: payload.command || '',
        args: Array.isArray(payload.args) ? payload.args : [],
        fullCommand: payload.fullCommand || `${payload.command || ''} ${(payload.args || []).join(' ')}`.trim(),
        cwd: payload.cwd || '',
        startTime: payload.startTime || event.timestamp,
        endTime: payload.endTime || event.timestamp,
        durationMs: payload.durationMs || 0,
        exitCode: payload.exitCode ?? 1,
        signal: payload.signal || null,
        status: IncidentStatus.REGRESSED,
        stdout: payload.stdoutSnippet || payload.stdout || '',
        stderr: payload.stderrSnippet || payload.stderr || '',
        normalizedError: payload.normalizedError || '',
        evidenceHash: payload.evidenceHash || '',
        evidenceRef: payload.evidenceRef || '',
        diagnostic: payload.diagnostic || null,
        isTruncated: Boolean(payload.isTruncated),
        git: payload.git || { isGit: false },
        environment: payload.environment || {},
        regressionOf: payload.regressionOf ? String(payload.regressionOf) : null,
        recoveryAttempts: [],
        _projection: {
          notice: 'DERIVED AND REBUILDABLE. Authoritative source of truth is .rewind/journal.jsonl',
          projectionSchemaVersion: PROJECTION_SCHEMA_VERSION,
          derivedFromSequence: event.sequence,
          projectedAt: event.timestamp
        }
      };
      incidents.set(id, normalizeRecordToCurrentSchema(newRecord));
      break;
    }

    case 'recovery.proposed': {
      const existing = incidents.get(id);
      if (!existing) break;

      assertValidIncidentTransition(existing.status, IncidentStatus.OPEN, id);

      const payload = event.payload || {};
      const currentAttempts = Array.isArray(existing.recoveryAttempts) ? [...existing.recoveryAttempts] : [];
      const attemptId = payload.attemptId || (currentAttempts.length + 1);
      const isFixed = Boolean(payload.isFixed || payload.status === RecoveryAttemptStatus.FIXED);
      const status = payload.status || (isFixed ? RecoveryAttemptStatus.FIXED : RecoveryAttemptStatus.PROPOSED);
      const quality = payload.evidenceQuality || (isFixed ? EvidenceQuality.UNVERIFIED : (payload.change ? EvidenceQuality.USER_REPORTED : EvidenceQuality.UNVERIFIED));

      const newAttempt = {
        id: attemptId,
        createdAt: event.timestamp,
        cause: payload.cause || null,
        causeProvenance: payload.cause ? (payload.causeProvenance || ProvenanceType.USER_REPORTED) : null,
        change: payload.change || null,
        changeProvenance: payload.change ? (payload.changeProvenance || ProvenanceType.USER_REPORTED) : null,
        verifyCmd: payload.verifyCmd || null,
        verifyCmdProvenance: payload.verifyCmd ? (payload.verifyCmdProvenance || ProvenanceType.USER_REPORTED) : null,
        observedChanges: payload.observedChanges || null,
        status,
        isExternal: Boolean(payload.isExternal),
        externalVerification: payload.externalVerification || null,
        evidenceQuality: quality,
        source: payload.source || 'cli',
        baselineFailed: Boolean(payload.baselineFailed),
        verificationRuns: []
      };

      const updated = {
        ...existing,
        status: IncidentStatus.OPEN,
        recoveryAttempts: [...currentAttempts, newAttempt],
        _projection: {
          notice: 'DERIVED AND REBUILDABLE. Authoritative source of truth is .rewind/journal.jsonl',
          projectionSchemaVersion: PROJECTION_SCHEMA_VERSION,
          derivedFromSequence: event.sequence,
          projectedAt: event.timestamp
        }
      };
      incidents.set(id, normalizeRecordToCurrentSchema(updated));
      break;
    }

    case 'recovery.fixed': {
      const existing = incidents.get(id);
      if (!existing) break;

      const payload = event.payload || {};
      const currentAttempts = Array.isArray(existing.recoveryAttempts) ? [...existing.recoveryAttempts] : [];
      const targetAttemptId = payload.attemptId || (currentAttempts.length > 0 ? currentAttempts[currentAttempts.length - 1].id : 1);
      const attemptIndex = currentAttempts.findIndex((a) => String(a.id) === String(targetAttemptId));

      if (attemptIndex !== -1) {
        const targetAttempt = { ...currentAttempts[attemptIndex] };
        assertValidAttemptTransition(targetAttempt.status, RecoveryAttemptStatus.FIXED, targetAttemptId);
        targetAttempt.status = RecoveryAttemptStatus.FIXED;
        targetAttempt.evidenceQuality = EvidenceQuality.UNVERIFIED;
        if (payload.observedChanges) {
          targetAttempt.observedChanges = payload.observedChanges;
        }
        currentAttempts[attemptIndex] = targetAttempt;

        const updated = {
          ...existing,
          recoveryAttempts: currentAttempts,
          _projection: {
            notice: 'DERIVED AND REBUILDABLE. Authoritative source of truth is .rewind/journal.jsonl',
            projectionSchemaVersion: PROJECTION_SCHEMA_VERSION,
            derivedFromSequence: event.sequence,
            projectedAt: event.timestamp
          }
        };
        incidents.set(id, normalizeRecordToCurrentSchema(updated));
      }
      break;
    }

    case 'verification.run': {
      const existing = incidents.get(id);
      if (!existing) break;

      const payload = event.payload || {};
      const currentAttempts = Array.isArray(existing.recoveryAttempts) ? [...existing.recoveryAttempts] : [];
      const targetAttemptId = payload.attemptId || (currentAttempts.length > 0 ? currentAttempts[currentAttempts.length - 1].id : 1);
      const attemptIndex = currentAttempts.findIndex(a => String(a.id) === String(targetAttemptId));

      if (attemptIndex !== -1) {
        const targetAttempt = { ...currentAttempts[attemptIndex] };
        const currentRuns = Array.isArray(targetAttempt.verificationRuns) ? [...targetAttempt.verificationRuns] : [];
        const runId = payload.runId || (currentRuns.length + 1);
        const isPassed = payload.exitCode === 0;

        const newRun = {
          id: runId,
          startedAt: payload.startedAt || event.timestamp,
          completedAt: event.timestamp,
          command: payload.command || targetAttempt.verifyCmd || '',
          exitCode: payload.exitCode ?? (isPassed ? 0 : 1),
          durationMs: payload.durationMs || 0,
          output: payload.output || '',
          outputHash: payload.outputHash || crypto.createHash('sha256').update(payload.output || '', 'utf8').digest('hex'),
          environmentFingerprint: payload.environmentFingerprint || existing.environment?.fingerprint || '',
          environment: payload.environment || null,
          git: payload.git || null,
          result: isPassed ? 'PASSED' : 'FAILED',
          provenance: payload.provenance || ProvenanceType.DIRECTLY_VERIFIED
        };

        if (targetAttempt.status !== RecoveryAttemptStatus.VERIFIED) {
          const targetAttemptStatus = isPassed ? RecoveryAttemptStatus.VERIFIED : RecoveryAttemptStatus.FAILED;
          assertValidAttemptTransition(targetAttempt.status, targetAttemptStatus, targetAttemptId);
          targetAttempt.status = targetAttemptStatus;
        }
        targetAttempt.evidenceQuality = isPassed ? EvidenceQuality.DIRECT : EvidenceQuality.DIRECT;
        if (isPassed) {
          targetAttempt.isExternal = false;
          targetAttempt.locallyVerified = true;
        }
        targetAttempt.verificationRuns = [...currentRuns, newRun];
        currentAttempts[attemptIndex] = targetAttempt;

        const updatedIncidentStatus = (isPassed || existing.status === IncidentStatus.RECOVERED) ? IncidentStatus.RECOVERED : existing.status;
        assertValidIncidentTransition(existing.status, updatedIncidentStatus, id);

        const updated = {
          ...existing,
          status: updatedIncidentStatus,
          recoveryAttempts: currentAttempts,
          _projection: {
            notice: 'DERIVED AND REBUILDABLE. Authoritative source of truth is .rewind/journal.jsonl',
            projectionSchemaVersion: PROJECTION_SCHEMA_VERSION,
            derivedFromSequence: event.sequence,
            projectedAt: event.timestamp
          }
        };
        incidents.set(id, normalizeRecordToCurrentSchema(updated));
      }
      break;
    }

    case 'incident.resolved': {
      const existing = incidents.get(id);
      if (!existing) break;

      assertValidIncidentTransition(existing.status, IncidentStatus.RESOLVED, id);

      const updated = {
        ...existing,
        status: IncidentStatus.RESOLVED,
        _projection: {
          notice: 'DERIVED AND REBUILDABLE. Authoritative source of truth is .rewind/journal.jsonl',
          projectionSchemaVersion: PROJECTION_SCHEMA_VERSION,
          derivedFromSequence: event.sequence,
          projectedAt: event.timestamp
        }
      };
      incidents.set(id, normalizeRecordToCurrentSchema(updated));
      break;
    }

    case 'observation.promoted': {
      const payload = event.payload || {};
      const newRecord = {
        id,
        fingerprint: payload.fingerprint || '',
        command: payload.command || '',
        args: Array.isArray(payload.args) ? payload.args : [],
        fullCommand: payload.fullCommand || `${payload.command || ''} ${(payload.args || []).join(' ')}`.trim(),
        cwd: payload.cwd || '',
        startTime: payload.startTime || event.timestamp,
        endTime: payload.endTime || event.timestamp,
        durationMs: payload.durationMs || 0,
        exitCode: payload.exitCode ?? 1,
        signal: payload.signal || null,
        status: IncidentStatus.OBSERVED,
        stdout: payload.stdoutSnippet || payload.stdout || '',
        stderr: payload.stderrSnippet || payload.stderr || '',
        normalizedError: payload.normalizedError || '',
        evidenceHash: payload.evidenceHash || '',
        evidenceRef: payload.evidenceRef || '',
        diagnostic: payload.diagnostic || null,
        isTruncated: Boolean(payload.isTruncated),
        git: payload.git || { isGit: false },
        environment: payload.environment || {},
        regressionOf: payload.regressionOf || null,
        recoveryAttempts: [],
        promotedFromObservation: payload.observationId || null,
        _projection: {
          notice: 'DERIVED AND REBUILDABLE. Authoritative source of truth is .rewind/journal.jsonl',
          projectionSchemaVersion: PROJECTION_SCHEMA_VERSION,
          derivedFromSequence: event.sequence,
          projectedAt: event.timestamp
        }
      };
      incidents.set(id, normalizeRecordToCurrentSchema(newRecord));
      break;
    }
  }

  return incidents.get(id) || null;
}

/**
 * Pure deterministic reducer that replays journal events in chronological sequence
 * to derive the complete set of active IncidentRecord views.
 *
 * @param {Array<object>} events - Ordered journal events
 * @returns {Map<string, import('./record.js').IncidentRecord>}
 */
export function projectEventsToRecords(events = []) {
  const incidents = new Map();

  for (const event of events) {
    applyEventToRecordMap(incidents, event);
  }

  return incidents;
}

/**
 * Pure deterministic reducer that replays journal events to derive
 * the complete set of Observation views.
 *
 * @param {Array<object>} events - Ordered journal events
 * @returns {Map<string, object>}
 */
export function projectEventsToObservations(events = []) {
  const observations = new Map();

  for (const event of events) {
    if (!event || !event.type) continue;

    if (event.type === 'observation.recorded') {
      const payload = event.payload || {};
      const obsId = String(payload.id || event.incidentId);
      observations.set(obsId, {
        id: obsId,
        fingerprint: payload.fingerprint || '',
        fingerprintVersion: inferFingerprintVersion(payload.fingerprint, payload.fingerprintVersion),
        command: payload.command || '',
        args: Array.isArray(payload.args) ? payload.args : [],
        fullCommand: payload.fullCommand || '',
        cwd: payload.cwd || '',
        durationMs: payload.durationMs || 0,
        exitCode: payload.exitCode ?? 1,
        signal: payload.signal || null,
        stderr: payload.stderr || '',
        stdout: payload.stdout || '',
        diagnostic: payload.diagnostic || null,
        diagnosticType: payload.diagnosticType || payload.diagnostic?.errorType || null,
        createdAt: payload.createdAt || event.timestamp,
        ttlExpiry: payload.ttlExpiry || null,
        promotedToIncident: payload.promotedToIncident || null,
        environment: payload.environment || {},
        git: payload.git || { isGit: false },
        _sequence: event.sequence
      });
    } else if (event.type === 'observation.promoted') {
      const payload = event.payload || {};
      const obsId = String(payload.observationId || '');
      if (obsId && observations.has(obsId)) {
        const obs = observations.get(obsId);
        obs.promotedToIncident = String(event.incidentId || payload.promotedToIncident);
      }
    }
  }

  return observations;
}

/**
 * Atomically renames a temporary file to destination path with cross-platform
 * resilience against Windows EPERM/EBUSY handle contention.
 *
 * @param {string} sourcePath
 * @param {string} destPath
 */
export function safeAtomicRenameSync(sourcePath, destPath) {
  try {
    fs.renameSync(sourcePath, destPath);
  } catch (err) {
    if (err.code === 'EPERM' || err.code === 'EEXIST' || err.code === 'EBUSY') {
      try {
        if (fs.existsSync(destPath)) {
          fs.unlinkSync(destPath);
        }
        fs.renameSync(sourcePath, destPath);
      } catch {
        fs.copyFileSync(sourcePath, destPath);
        try { fs.unlinkSync(sourcePath); } catch {}
      }
    } else {
      throw err;
    }
  }
}
