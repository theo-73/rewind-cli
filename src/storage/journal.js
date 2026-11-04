import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { canonicalStringify, computeCanonicalDigest } from './canonical.js';
import { safeAtomicRenameSync } from './projection.js';
import { redactSecrets } from '../sanitizer.js';
import { CliError } from '../errors.js';

export const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';
export const JOURNAL_FORMAT_VERSION = 1;
export const EVENT_SCHEMA_VERSION = 1;
export const CHECKPOINT_FORMAT_VERSION = 1;

/**
 * Custom error thrown when acquiring exclusive journal lock fails due to active contention.
 */
export class LockContentionError extends CliError {
  constructor(message, details = {}) {
    super(message, {
      code: 'ERR_LOCK_CONTENTION',
      exitCode: 1,
      details
    });
    this.name = 'LockContentionError';
  }
}

/**
 * Acquires an exclusive file lock for journal appends with conservative cross-platform safety.
 *
 * @param {string} lockPath
 * @param {object} [options]
 * @param {number} [options.timeoutMs=3000]
 * @param {number} [options.staleAgeMs=30000]
 * @returns {{ lockPath: string, release: () => void }}
 */
export function acquireJournalLock(lockPath, options = {}) {
  const timeoutMs = options.timeoutMs ?? 3000;
  const staleAgeMs = options.staleAgeMs ?? 30000;
  const startTime = Date.now();
  let retryDelay = 25;

  while (Date.now() - startTime < timeoutMs) {
    try {
      const fd = fs.openSync(lockPath, 'wx', 0o600);
      const lockPayload = JSON.stringify({
        pid: process.pid,
        hostname: os.hostname(),
        createdAt: new Date().toISOString()
      });
      fs.writeSync(fd, lockPayload);
      fs.fsyncSync(fd);
      fs.closeSync(fd);

      return {
        lockPath,
        release: () => {
          try {
            fs.unlinkSync(lockPath);
          } catch {
            // Ignore failure to delete on release
          }
        }
      };
    } catch (err) {
      if (err.code !== 'EEXIST') {
        throw new CliError(`Failed to create journal lock: ${err.message}`, { code: 'ERR_LOCK_FAILED' });
      }

      // Lock exists: inspect whether it is conclusively dead/stale
      try {
        const lockContent = fs.readFileSync(lockPath, 'utf8');
        const lockInfo = JSON.parse(lockContent);
        const lockAge = Date.now() - new Date(lockInfo.createdAt).getTime();

        if (lockAge > staleAgeMs && lockInfo.hostname === os.hostname() && typeof lockInfo.pid === 'number') {
          let processAlive = true;
          try {
            // Signal 0 tests process existence without killing it
            process.kill(lockInfo.pid, 0);
          } catch (killErr) {
            if (killErr.code === 'ESRCH') {
              processAlive = false;
            }
          }

          if (!processAlive) {
            // Process is confirmed dead on the same host: safe to reclaim
            try {
              fs.unlinkSync(lockPath);
              continue;
            } catch {
              // Another process may have unlinked it
            }
          }
        }
      } catch {
        // If lock file is unreadable or malformed, don't crash, just retry
        try {
          const lockStat = fs.statSync(lockPath);
          if (Date.now() - lockStat.mtimeMs > staleAgeMs) {
            fs.unlinkSync(lockPath);
            continue;
          }
        } catch {
          // File may have been removed or is completely inaccessible
        }
      }

      // Zero-CPU synchronous sleep before retry with jitter using standard SharedArrayBuffer + Atomics.wait
      const jitter = Math.floor(Math.random() * 10);
      const sleepTime = Math.min(200, retryDelay + jitter);
      try {
        const sab = new SharedArrayBuffer(4);
        const int32 = new Int32Array(sab);
        Atomics.wait(int32, 0, 0, sleepTime);
      } catch {
        // Fallback for restricted environments
        const waitEnd = Date.now() + sleepTime;
        while (Date.now() < waitEnd) {
          // Fallback busy wait
        }
      }
      retryDelay = Math.min(200, retryDelay * 1.5);
    }
  }

  throw new LockContentionError(
    `Could not acquire exclusive journal lock at "${lockPath}" within ${timeoutMs}ms. Another process is currently writing to the ledger.`,
    { lockPath, timeoutMs }
  );
}

/**
 * Creates and cryptographically seals an immutable journal event.
 *
 * @param {object} params
 * @param {string} params.type - Event type (e.g. 'failure.observed')
 * @param {string} params.incidentId - Associated Incident ID
 * @param {object} params.payload - Event payload data
 * @param {string} params.prevHash - Preceding event's chainHash (or GENESIS_HASH)
 * @param {number} params.sequence - Monotonically increasing sequence index (1-based)
 * @param {string} [params.timestamp] - Optional ISO timestamp
 * @param {string} [params.eventId] - Optional event UUID
 * @returns {object} - Complete sealed event envelope
 */
export function createEvent({
  type,
  incidentId,
  payload,
  prevHash,
  sequence,
  timestamp = new Date().toISOString(),
  eventId = `evt_${crypto.randomUUID().replace(/-/g, '')}`
}) {
  if (!type || typeof type !== 'string') {
    throw new Error('Event type must be a non-empty string');
  }
  if (!incidentId) {
    throw new Error('Event incidentId is required');
  }
  if (!payload || typeof payload !== 'object') {
    throw new Error('Event payload must be an object');
  }
  if (!prevHash || typeof prevHash !== 'string' || prevHash.length !== 64) {
    throw new Error(`Invalid prevHash: expected 64-character hex string, got "${prevHash}"`);
  }
  if (typeof sequence !== 'number' || sequence < 1 || !Number.isInteger(sequence)) {
    throw new Error(`Invalid sequence number: expected positive integer, got "${sequence}"`);
  }

  // Build the event content to be hashed
  const eventContent = {
    journalFormatVersion: JOURNAL_FORMAT_VERSION,
    eventSchemaVersion: EVENT_SCHEMA_VERSION,
    sequence,
    eventId,
    timestamp,
    type,
    incidentId: String(incidentId),
    payload
  };

  // 1. Layer 1: Canonical Event Hash
  const eventHash = computeCanonicalDigest(eventContent);

  // 2. Layer 2: Chain Hash combining predecessor and event hash
  const chainInput = `${prevHash}:${eventHash}`;
  const chainHash = crypto.createHash('sha256').update(chainInput, 'utf8').digest('hex');

  return {
    ...eventContent,
    prevHash,
    eventHash,
    chainHash
  };
}

/**
 * Reads all events from a journal.jsonl file with resilient non-crashing parsing.
 *
 * @param {string} journalPath
 * @returns {{ events: Array<any>, malformed: Array<{ lineNumber: number, raw: string, error: string }>, totalLines: number }}
 */
export function readJournalEvents(journalPath) {
  if (!fs.existsSync(journalPath)) {
    return { events: [], malformed: [], totalLines: 0 };
  }

  const content = fs.readFileSync(journalPath, 'utf8');
  if (!content.trim()) {
    return { events: [], malformed: [], totalLines: 0 };
  }

  const lines = content.split('\n');
  const events = [];
  const malformed = [];

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i].trim();
    if (!rawLine) continue; // Skip empty lines

    const lineNumber = i + 1;
    try {
      const parsed = JSON.parse(rawLine);
      events.push(parsed);
    } catch (parseErr) {
      malformed.push({
        lineNumber,
        raw: rawLine,
        error: parseErr.message
      });
    }
  }

  return {
    events,
    malformed,
    totalLines: lines.filter(l => l.trim().length > 0).length
  };
}

/**
 * Fast-path reader that retrieves the last sealed event from journal.jsonl in O(1)
 * without parsing the entire historical file.
 *
 * @param {string} journalPath
 * @returns {object|null}
 */
export function readLastJournalEvent(journalPath) {
  if (!fs.existsSync(journalPath)) {
    return null;
  }

  try {
    const stats = fs.statSync(journalPath);
    if (stats.size === 0) {
      return null;
    }

    const readSize = Math.min(stats.size, 65536);
    const buffer = Buffer.alloc(readSize);
    const fd = fs.openSync(journalPath, 'r');
    try {
      fs.readSync(fd, buffer, 0, readSize, stats.size - readSize);
    } finally {
      fs.closeSync(fd);
    }

    // Find the last non-empty line by scanning backwards
    let end = readSize;
    while (end > 0 && (buffer[end - 1] === 0x0A || buffer[end - 1] === 0x0D || buffer[end - 1] === 0x20 || buffer[end - 1] === 0x09)) {
      end--;
    }

    if (end === 0) {
      return null;
    }

    let start = end - 1;
    while (start >= 0 && buffer[start] !== 0x0A) {
      start--;
    }
    start = start + 1; // start of the last line

    const lineStr = buffer.subarray(start, end).toString('utf8').trim();
    if (lineStr) {
      const parsed = JSON.parse(lineStr);
      if (parsed && typeof parsed === 'object' && typeof parsed.sequence === 'number' && parsed.chainHash) {
        return parsed;
      }
    }
  } catch {
    // Fall back to full journal read on any fast-path error or partial read
  }

  const { events } = readJournalEvents(journalPath);
  return events.length > 0 ? events[events.length - 1] : null;
}

/**
 * Saves large process output into the isolated evidence store (.rewind/evidence/<hash>.log).
 *
 * @param {string} ledgerDir
 * @param {string} outputContent
 * @returns {{ evidenceHash: string, evidenceRef: string }}
 */
export function saveEvidenceArtifact(ledgerDir, outputContent) {
  const content = typeof outputContent === 'string' ? redactSecrets(outputContent) : '';
  const evidenceHash = crypto.createHash('sha256').update(content, 'utf8').digest('hex');
  const evidenceDir = path.join(ledgerDir, 'evidence');
  const filename = `${evidenceHash}.log`;
  const evidencePath = path.join(evidenceDir, filename);

  if (!fs.existsSync(evidenceDir)) {
    fs.mkdirSync(evidenceDir, { recursive: true, mode: 0o700 });
  }

  if (!fs.existsSync(evidencePath)) {
    // Atomic write to avoid partial evidence files
    const tmpPath = path.join(ledgerDir, 'tmp', `ev_${Date.now()}_${crypto.randomUUID().slice(0, 8)}.tmp`);
    fs.writeFileSync(tmpPath, content, { mode: 0o600 });
    fs.renameSync(tmpPath, evidencePath);
  }

  return {
    evidenceHash,
    evidenceRef: `evidence/${filename}`
  };
}

/**
 * Reads the local trusted checkpoint metadata from .rewind/checkpoint.json.
 *
 * @param {string} ledgerDir
 * @returns {object|null}
 */
export function readCheckpoint(ledgerDir) {
  const checkpointPath = path.join(ledgerDir, 'checkpoint.json');
  if (!fs.existsSync(checkpointPath)) {
    return null;
  }

  try {
    const content = fs.readFileSync(checkpointPath, 'utf8');
    return JSON.parse(content);
  } catch {
    return null;
  }
}

/**
 * Atomically writes the trusted checkpoint metadata to .rewind/checkpoint.json.
 *
 * @param {string} ledgerDir
 * @param {object} checkpointData
 */
export function writeCheckpoint(ledgerDir, checkpointData) {
  const checkpointPath = path.join(ledgerDir, 'checkpoint.json');
  const tmpDir = path.join(ledgerDir, 'tmp');

  if (!fs.existsSync(tmpDir)) {
    fs.mkdirSync(tmpDir, { recursive: true, mode: 0o700 });
  }

  const payload = {
    checkpointFormatVersion: CHECKPOINT_FORMAT_VERSION,
    journalId: checkpointData.journalId || 'rewind-ledger',
    headSequence: checkpointData.headSequence,
    headEventId: checkpointData.headEventId,
    headChainHash: checkpointData.headChainHash,
    eventCount: checkpointData.eventCount,
    highestIncidentId: typeof checkpointData.highestIncidentId === 'number' ? checkpointData.highestIncidentId : null,
    updatedAt: new Date().toISOString()
  };

  const canonicalJson = canonicalStringify(payload);
  const tmpPath = path.join(tmpDir, `chk_${Date.now()}_${crypto.randomUUID().slice(0, 8)}.tmp`);

  const fd = fs.openSync(tmpPath, 'w', 0o600);
  try {
    fs.writeSync(fd, canonicalJson + '\n');
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }

  safeAtomicRenameSync(tmpPath, checkpointPath);
}

/**
 * Appends an event to the authoritative journal (.rewind/journal.jsonl) with full locking,
 * fsync durability, and checkpoint updating in O(1) time.
 *
 * @param {string} ledgerDir - Absolute path to .rewind directory
 * @param {object} eventInput
 * @param {string} eventInput.type - Event type
 * @param {string} eventInput.incidentId - Incident ID (or 'AUTO' to atomically allocate)
 * @param {object} eventInput.payload - Event payload
 * @param {object} [options]
 * @returns {object} - The sealed event written to the journal
 */
export function appendJournalEvent(ledgerDir, eventInput, options = {}) {
  const lockPath = path.join(ledgerDir, 'journal.lock');
  const journalPath = path.join(ledgerDir, 'journal.jsonl');
  const lock = acquireJournalLock(lockPath, options);

  try {
    // 1. Read last event in O(1) to determine sequence and prevHash
    const lastEvent = readLastJournalEvent(journalPath);
    let sequence = 1;
    let prevHash = GENESIS_HASH;

    if (lastEvent) {
      sequence = lastEvent.sequence + 1;
      prevHash = lastEvent.chainHash;
    }

    // 2. Read or derive trusted checkpoint to determine sequence and atomic incident ID allocation
    const checkpoint = readCheckpoint(ledgerDir);
    let highestIncidentId = checkpoint?.highestIncidentId;

    if (typeof highestIncidentId !== 'number') {
      highestIncidentId = 0;
      if (fs.existsSync(journalPath) && fs.statSync(journalPath).size > 0) {
        const { events } = readJournalEvents(journalPath);
        for (const ev of events) {
          const numId = Number.parseInt(ev.incidentId, 10);
          if (!Number.isNaN(numId) && numId > highestIncidentId) {
            highestIncidentId = numId;
          }
        }
      }
    }

    let allocatedIncidentId = eventInput.incidentId;
    if (!allocatedIncidentId || allocatedIncidentId === 'AUTO') {
      highestIncidentId += 1;
      allocatedIncidentId = String(highestIncidentId);
    } else {
      const numId = Number.parseInt(allocatedIncidentId, 10);
      if (!Number.isNaN(numId) && numId > highestIncidentId) {
        highestIncidentId = numId;
      }
    }

    // 3. Create the cryptographically sealed event
    const event = createEvent({
      type: eventInput.type,
      incidentId: allocatedIncidentId,
      payload: eventInput.payload,
      prevHash,
      sequence
    });

    // 4. Serialize event to single-line canonical JSON
    const canonicalLine = canonicalStringify(event) + '\n';

    // 5. Append to journal.jsonl with fsync durability
    const journalFd = fs.openSync(journalPath, 'a', 0o600);
    try {
      fs.writeSync(journalFd, canonicalLine);
      fs.fsyncSync(journalFd);
    } finally {
      fs.closeSync(journalFd);
    }

    // 6. Update local trusted checkpoint
    const eventCount = sequence;

    writeCheckpoint(ledgerDir, {
      headSequence: event.sequence,
      headEventId: event.eventId,
      headChainHash: event.chainHash,
      eventCount,
      highestIncidentId
    });

    return event;
  } finally {
    lock.release();
  }
}
