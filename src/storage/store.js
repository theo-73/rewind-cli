import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { isValidRecord, normalizeRecordToCurrentSchema, boundOutput } from './record.js';
import { IncidentStatus, RecoveryAttemptStatus, ProvenanceType, EvidenceQuality, ProofTier, computeProofTier } from './state.js';
import { computeFingerprint, inferFingerprintVersion } from './fingerprint.js';
import { evaluateStaleness } from './staleness.js';
import { extractNegativeMemory } from './negative_memory.js';
import { analyzeEvidenceConflicts } from './contradiction.js';
import { evaluateSurfacing } from './surfacing.js';
import {
  appendJournalEvent,
  readJournalEvents,
  readLastJournalEvent,
  readCheckpoint,
  writeCheckpoint,
  saveEvidenceArtifact,
  createEvent,
  acquireJournalLock,
  GENESIS_HASH
} from './journal.js';
import { projectEventsToRecords, projectEventsToObservations, applyEventToRecordMap, safeAtomicRenameSync, PROJECTION_SCHEMA_VERSION } from './projection.js';
import { canonicalStringify } from './canonical.js';
import { verifyLedgerIntegrity } from './integrity.js';
import { analyzePatternsFromJournal } from './patterns.js';
import { buildAgentContext } from './context.js';
import { runDoctorDiagnostics, executeDoctorRepair } from './doctor.js';
import { captureSafeEnvironment } from '../environment.js';
import { readGitMetadata } from '../git.js';
import { CliError, UsageError } from '../errors.js';
import { redactRecordForStorage, isTrivialVerifyCommand, redactSecrets, redactCommandArgs, redactCommandString } from '../sanitizer.js';

/**
 * Normalizes an incident ID string by stripping common prefixes like "#", "RW-", or "rw-".
 *
 * @param {string|number} id
 * @returns {string}
 */
export function normalizeId(id) {
  if (id === null || id === undefined) return '';
  return String(id).replace(/^(?:RW-|#)/i, '').trim();
}

export class StorageEngine {
  /**
   * @param {string} ledgerDir - Path to .rewind directory
   */
  constructor(ledgerDir) {
    this.ledgerDir = path.resolve(ledgerDir);
    this.recordsDir = path.join(this.ledgerDir, 'records');
    this.evidenceDir = path.join(this.ledgerDir, 'evidence');
    this.tmpDir = path.join(this.ledgerDir, 'tmp');
    this.quarantineDir = path.join(this.ledgerDir, 'quarantine');
    this.journalPath = path.join(this.ledgerDir, 'journal.jsonl');
    this.dbPath = path.join(this.ledgerDir, 'projection.db');

    /** @type {Map<string, import('./record.js').IncidentRecord>} */
    this.index = new Map();
    /** @type {Map<string, Array<import('./record.js').IncidentRecord>>} */
    this.fingerprintIndex = new Map();
    /** @type {Map<string, object>} */
    this.observations = new Map();
    /** @type {Map<string, Array<object>>} */
    this.obsFingerprintIndex = new Map();
    this.highestId = 0;
    /** @type {Array<{ file: string, reason: string, quarantinedAt: string }>} */
    this.quarantined = [];
    this.initialized = false;
  }

  /**
   * Initializes the storage directory layout, cleans orphan temp files,
   * verifies trusted checkpoint against journal tail, and loads projections.
   */
  init() {
    if (this.initialized && this.db) {
      return this;
    }

    // 1. Ensure directory hierarchy exists with secure permissions (0o700)
    fs.mkdirSync(this.ledgerDir, { recursive: true, mode: 0o700 });
    fs.mkdirSync(this.evidenceDir, { recursive: true, mode: 0o700 });
    fs.mkdirSync(this.tmpDir, { recursive: true, mode: 0o700 });
    fs.mkdirSync(this.quarantineDir, { recursive: true, mode: 0o700 });

    // 2. Clean orphaned temporary files in tmpDir
    this.cleanOrphanedTempFiles();
    
    // 3. Initialize SQLite Projection DB
    this.initDatabase();

    // 4. Clean expired observations
    this.cleanupExpiredObservations();

    // 5. Fast-path initialization: check if checkpoint matches journal tail and records are valid
    const checkpoint = readCheckpoint(this.ledgerDir);
    const lastEvent = readLastJournalEvent(this.journalPath);

    const isJournalEmpty = !fs.existsSync(this.journalPath) || fs.statSync(this.journalPath).size === 0;

    // Legacy migration: if records/ directory exists with JSON files, rebuild into SQLite and journal.
    let needsLegacyMigration = false;
    try {
      if (fs.existsSync(this.recordsDir)) {
        const hasLegacyFiles = fs.readdirSync(this.recordsDir).some(f => f.endsWith('.json'));
        if (hasLegacyFiles) {
          needsLegacyMigration = true;
        } else {
          fs.rmSync(this.recordsDir, { recursive: true, force: true });
        }
      }
    } catch {}

    if (needsLegacyMigration) {
      this.rebuildIndex({ syncDisk: true });
      fs.rmSync(this.recordsDir, { recursive: true, force: true });
      this.initialized = true;
      return this;
    }

    if (isJournalEmpty) {
      this.setProjectionSchemaVersion(PROJECTION_SCHEMA_VERSION);
      this.initialized = true;
      return this;
    }

    if (checkpoint && lastEvent && checkpoint.headSequence === lastEvent.sequence && checkpoint.headChainHash === lastEvent.chainHash) {
      // Checkpoint is valid and strictly in sync with journal head: load from SQLite only if schema version matches
      const storedVersion = this.getProjectionSchemaVersion();
      if (storedVersion === PROJECTION_SCHEMA_VERSION) {
        if (this.loadFromDatabase()) {
          this.initialized = true;
          return this;
        }
      }
    }

    // Otherwise, rebuild index from authoritative journal
    this.rebuildIndex({ syncDisk: true });

    this.initialized = true;
    return this;
  }

  /**
   * Closes the SQLite database connection safely.
   */
  close() {
    if (this.db) {
      try {
        this.db.close();
      } catch (err) {
        // Ignore errors if already closed
      }
      this.db = null;
      this.initialized = false;
    }
  }

  initDatabase() {
    this.db = new DatabaseSync(this.dbPath);
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS records (
        id TEXT PRIMARY KEY,
        data TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS metadata (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS observations (
        id TEXT PRIMARY KEY,
        fingerprint TEXT NOT NULL,
        command TEXT,
        exitCode INTEGER,
        stderr TEXT,
        diagnosticType TEXT,
        createdAt TEXT NOT NULL,
        promotedToIncident TEXT,
        ttlExpiry TEXT,
        data TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_obs_fingerprint ON observations(fingerprint);
      CREATE INDEX IF NOT EXISTS idx_obs_ttl ON observations(ttlExpiry);
      CREATE INDEX IF NOT EXISTS idx_obs_created ON observations(createdAt);
    `);
    
    // Optimize SQLite for single-node local performance and prevent lock contention
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = NORMAL;
      PRAGMA temp_store = MEMORY;
      PRAGMA busy_timeout = 5000;
    `);

    this.insertStmt = this.db.prepare('INSERT OR REPLACE INTO records (id, data) VALUES (?, ?)');
    this.selectAllStmt = this.db.prepare('SELECT id, data FROM records');
    this.deleteAllStmt = this.db.prepare('DELETE FROM records');

    this.getMetaStmt = this.db.prepare('SELECT value FROM metadata WHERE key = ?');
    this.setMetaStmt = this.db.prepare('INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)');

    this.insertObsStmt = this.db.prepare('INSERT OR REPLACE INTO observations (id, fingerprint, command, exitCode, stderr, diagnosticType, createdAt, promotedToIncident, ttlExpiry, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
    this.selectAllObsStmt = this.db.prepare('SELECT id, data FROM observations');
    this.deleteExpiredObsStmt = this.db.prepare("DELETE FROM observations WHERE ttlExpiry IS NOT NULL AND ttlExpiry <= ? AND (promotedToIncident IS NULL OR promotedToIncident = '')");
    this.updateObsPromotedStmt = this.db.prepare('UPDATE observations SET promotedToIncident = ?, data = ? WHERE id = ?');
    this.deleteAllObsStmt = this.db.prepare('DELETE FROM observations');
  }

  /**
   * Retrieves the current projection schema version from SQLite metadata table.
   *
   * @returns {number|null}
   */
  getProjectionSchemaVersion() {
    try {
      if (!this.getMetaStmt) return null;
      const row = this.getMetaStmt.get('projectionSchemaVersion');
      return row ? Number.parseInt(row.value, 10) : null;
    } catch {
      return null;
    }
  }

  /**
   * Sets the projection schema version in the SQLite metadata table.
   *
   * @param {number} [version=PROJECTION_SCHEMA_VERSION]
   */
  setProjectionSchemaVersion(version = PROJECTION_SCHEMA_VERSION) {
    try {
      if (!this.setMetaStmt) return;
      this.setMetaStmt.run('projectionSchemaVersion', String(version));
    } catch {}
  }

  /**
   * Fast-path reader that loads derived incident records directly from SQLite projection DB.
   *
   * @returns {boolean} - true if records loaded successfully
   */
  loadFromDatabase() {
    this.index.clear();
    this.fingerprintIndex.clear();
    this.observations.clear();
    this.obsFingerprintIndex.clear();
    this.highestId = 0;
    this.quarantined = [];

    try {
      const rows = this.selectAllStmt.all();
      if (rows.length === 0) return false;

      for (const row of rows) {
        try {
          const parsed = JSON.parse(row.data);
          if (!isValidRecord(parsed)) {
            continue;
          }
          const record = normalizeRecordToCurrentSchema(parsed);
          const id = String(record.id);
          this.index.set(id, record);

          if (record.fingerprint) {
            let list = this.fingerprintIndex.get(record.fingerprint);
            if (!list) {
              list = [];
              this.fingerprintIndex.set(record.fingerprint, list);
            }
            list.push(record);
          }

          const numId = Number.parseInt(id, 10);
          if (!Number.isNaN(numId) && numId > this.highestId) {
            this.highestId = numId;
          }
        } catch (err) {
          // Skip corrupt rows
        }
      }

      if (this.selectAllObsStmt) {
        const obsRows = this.selectAllObsStmt.all();
        for (const row of obsRows) {
          try {
            const parsed = JSON.parse(row.data);
            this.observations.set(row.id, parsed);
            if (parsed.fingerprint) {
              let oList = this.obsFingerprintIndex.get(parsed.fingerprint);
              if (!oList) {
                oList = [];
                this.obsFingerprintIndex.set(parsed.fingerprint, oList);
              }
              oList.push(parsed);
            }
          } catch (err) {}
        }
      }

      return true;
    } catch (err) {
      return false;
    }
  }

  /**
   * Syncs the entire memory map to SQLite. Used during rebuild.
   */
  writeProjectedRecordsToDatabase() {
    this.db.exec('BEGIN TRANSACTION');
    try {
      this.deleteAllStmt.run();
      for (const [id, record] of this.index.entries()) {
        this.insertStmt.run(id, JSON.stringify(record));
      }
      if (this.deleteAllObsStmt) {
        this.deleteAllObsStmt.run();
        for (const [id, obs] of this.observations.entries()) {
          this.insertObsStmt.run(
            id,
            obs.fingerprint || '',
            obs.command || '',
            typeof obs.exitCode === 'number' ? obs.exitCode : null,
            obs.stderr || '',
            obs.diagnosticType || null,
            obs.createdAt || '',
            obs.promotedToIncident || null,
            obs.ttlExpiry || null,
            JSON.stringify(obs)
          );
        }
      }
      this.setProjectionSchemaVersion(PROJECTION_SCHEMA_VERSION);
      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
  }

  /**
   * Atomically writes a single projected incident record to SQLite.
   *
   * @param {import('./record.js').IncidentRecord} record
   */
  writeSingleProjectedRecordToDatabase(record) {
    if (!record || !record.id) return;
    this.insertStmt.run(String(record.id), JSON.stringify(record));
  }

  /**
   * Incrementally updates in-memory index with a single sealed journal event and writes
   * the single projected record file to disk in O(1) time.
   *
   * @param {object} event
   * @param {object} [options={}]
   * @returns {import('./record.js').IncidentRecord|null}
   */
  applyJournalEvent(event, options = {}) {
    const syncDisk = options.syncDisk !== false;
    const updated = applyEventToRecordMap(this.index, event);

    if (updated) {
      const strId = String(updated.id);
      this.index.set(strId, updated);

      if (updated.fingerprint) {
        let list = this.fingerprintIndex.get(updated.fingerprint);
        if (!list) {
          list = [];
          this.fingerprintIndex.set(updated.fingerprint, list);
        }
        const existingIdx = list.findIndex(r => String(r.id) === strId);
        if (existingIdx !== -1) {
          list[existingIdx] = updated;
        } else {
          list.push(updated);
        }
      }

      const numId = Number.parseInt(strId, 10);
      if (!Number.isNaN(numId) && numId > this.highestId) {
        this.highestId = numId;
      }

      if (syncDisk) {
        this.writeSingleProjectedRecordToDatabase(updated);
      }

      return updated;
    }

    return null;
  }

  /**
   * Safely deletes orphaned .tmp files left over from crashes or aborted writes.
   */
  cleanOrphanedTempFiles() {
    try {
      if (fs.existsSync(this.tmpDir)) {
        const files = fs.readdirSync(this.tmpDir);
        for (const file of files) {
          if (file.endsWith('.tmp')) {
            try {
              fs.unlinkSync(path.join(this.tmpDir, file));
            } catch {
              // Ignore failure to delete individual temp file
            }
          }
        }
      }
    } catch {
      // Directory read failed
    }
  }

  rebuildIndex(options = {}) {
    if (!this.db) {
      this.initDatabase();
    }
    const forceSyncDisk = Boolean(options.syncDisk);
    this.index.clear();
    this.fingerprintIndex.clear();
    this.observations.clear();
    this.obsFingerprintIndex.clear();
    this.highestId = 0;
    this.quarantined = [];

    // Scan recordsDir for any corrupted or unparseable files that need quarantine
    const quarantinedIds = new Set();
    if (fs.existsSync(this.recordsDir)) {
      let recordFiles = [];
      try {
        recordFiles = fs.readdirSync(this.recordsDir);
      } catch {
        // Ignore
      }

      for (const file of recordFiles) {
        if (!file.endsWith('.json')) continue;
        const filePath = path.join(this.recordsDir, file);
        try {
          const content = fs.readFileSync(filePath, 'utf8');
          const parsed = JSON.parse(content);
          if (!isValidRecord(parsed)) {
            this.quarantineFile(filePath, file, 'Schema validation failed: missing required fields');
            quarantinedIds.add(file.replace(/\.json$/, ''));
          }
        } catch (parseErr) {
          this.quarantineFile(filePath, file, `Malformed JSON: ${parseErr.message}`);
          quarantinedIds.add(file.replace(/\.json$/, ''));
        }
      }
    }

    // Read events from the authoritative journal
    const { events, malformed } = readJournalEvents(this.journalPath);

    if (events.length > 0) {
      // 1. Crash Consistency check: if checkpoint lagged behind valid journal head, fast-forward it
      const checkpoint = readCheckpoint(this.ledgerDir);
      const lastEvent = events[events.length - 1];
      const needsSync = forceSyncDisk || !checkpoint || checkpoint.headSequence < lastEvent.sequence;

      if (!checkpoint || checkpoint.headSequence < lastEvent.sequence) {
        let maxIncId = 0;
        for (const ev of events) {
          const numId = Number.parseInt(ev.incidentId, 10);
          if (!Number.isNaN(numId) && numId > maxIncId) {
            maxIncId = numId;
          }
        }
        writeCheckpoint(this.ledgerDir, {
          headSequence: lastEvent.sequence,
          headEventId: lastEvent.eventId,
          headChainHash: lastEvent.chainHash,
          eventCount: events.length,
          highestIncidentId: maxIncId
        });
      }

      // 2. Replay all events through the pure projection reducer
      const projectedRecords = projectEventsToRecords(events);

      for (const [id, record] of projectedRecords.entries()) {
        if (quarantinedIds.has(id)) {
          continue;
        }

        this.index.set(id, record);

        if (record.fingerprint) {
          let list = this.fingerprintIndex.get(record.fingerprint);
          if (!list) {
            list = [];
            this.fingerprintIndex.set(record.fingerprint, list);
          }
          list.push(record);
        }

        const numId = Number.parseInt(id, 10);
        if (!Number.isNaN(numId) && numId > this.highestId) {
          this.highestId = numId;
        }
      }

      const projectedObservations = projectEventsToObservations(events);
      for (const [id, obs] of projectedObservations.entries()) {
        this.observations.set(id, obs);
        if (obs.fingerprint) {
          let list = this.obsFingerprintIndex.get(obs.fingerprint);
          if (!list) {
            list = [];
            this.obsFingerprintIndex.set(obs.fingerprint, list);
          }
          list.push(obs);
        }
      }

      // 3. Sync derived projection files to disk ONLY when needed (e.g. initial generation or head sequence change)
      if (needsSync) {
        this.writeProjectedRecordsToDatabase();
      }
    } else if (fs.existsSync(this.recordsDir)) {
      // Legacy ledger fallback: migrate existing records to event journal
      let filenames = [];
      try {
        filenames = fs.readdirSync(this.recordsDir);
      } catch {
        return;
      }

      const legacyRecords = [];
      for (const filename of filenames) {
        if (!filename.endsWith('.json')) continue;
        const filePath = path.join(this.recordsDir, filename);

        let content;
        try {
          content = fs.readFileSync(filePath, 'utf8');
          const parsed = JSON.parse(content);
          if (isValidRecord(parsed)) {
            legacyRecords.push(normalizeRecordToCurrentSchema(parsed));
          }
        } catch {
          // Ignore unreadable legacy files
        }
      }

      // Sort legacy records numerically by ID
      legacyRecords.sort((a, b) => Number(a.id) - Number(b.id));

      for (const rec of legacyRecords) {
        // Synthesize initial failure event
        appendJournalEvent(this.ledgerDir, {
          type: rec.status === IncidentStatus.REGRESSED ? 'regression.detected' : 'failure.observed',
          incidentId: rec.id,
          payload: {
            command: rec.command || '',
            args: Array.isArray(rec.args) ? rec.args : [],
            fullCommand: rec.fullCommand || `${rec.command || ''} ${(rec.args || []).join(' ')}`.trim(),
            cwd: rec.cwd || '',
            exitCode: typeof rec.exitCode === 'number' ? rec.exitCode : 1,
            signal: rec.signal || null,
            durationMs: typeof rec.durationMs === 'number' ? rec.durationMs : 0,
            fingerprint: rec.fingerprint || '',
            normalizedError: rec.normalizedError || '',
            evidenceHash: rec.evidenceHash || '',
            evidenceRef: rec.evidenceRef || '',
            stderrSnippet: rec.stderr || '',
            stdoutSnippet: rec.stdout || '',
            isTruncated: Boolean(rec.isTruncated),
            environment: rec.environment || {},
            git: rec.git || { isGit: false },
            regressionOf: rec.regressionOf || null
          }
        });

        // Synthesize recovery attempts if any
        if (Array.isArray(rec.recoveryAttempts)) {
          for (const att of rec.recoveryAttempts) {
            appendJournalEvent(this.ledgerDir, {
              type: 'recovery.proposed',
              incidentId: rec.id,
              payload: {
                attemptId: att.id || 1,
                cause: att.cause || null,
                change: att.change || null,
                verifyCmd: att.verifyCmd || null
              }
            });

            if (Array.isArray(att.verificationRuns)) {
              for (const run of att.verificationRuns) {
                appendJournalEvent(this.ledgerDir, {
                  type: 'verification.run',
                  incidentId: rec.id,
                  payload: {
                    attemptId: att.id || 1,
                    runId: run.id || 1,
                    command: run.command || '',
                    exitCode: typeof run.exitCode === 'number' ? run.exitCode : 0,
                    durationMs: typeof run.durationMs === 'number' ? run.durationMs : 0,
                    output: run.output || '',
                    outputHash: run.outputHash || crypto.createHash('sha256').update(run.output || '', 'utf8').digest('hex'),
                    environmentFingerprint: run.environmentFingerprint || '',
                    result: run.result || (run.exitCode === 0 ? 'PASSED' : 'FAILED')
                  }
                });
              }
            }
          }
        }
      }

      // Re-read newly generated journal
      const reloaded = readJournalEvents(this.journalPath);
      const replayed = projectEventsToRecords(reloaded.events);

      for (const [id, record] of replayed.entries()) {
        this.index.set(id, record);
        const numId = Number.parseInt(id, 10);
        if (!Number.isNaN(numId) && numId > this.highestId) {
          this.highestId = numId;
        }
      }

      this.writeProjectedRecordsToDatabase();
    }
  }

  /**
   * Rebuilds all derived incident files and in-memory indexes by replaying the authoritative journal.
   * Never modifies or alters journal.jsonl.
   *
   * @returns {{ eventsReplayed: number, incidentsDerived: number }}
   */
  rebuildProjections() {
    if (!this.initialized) {
      this.init();
    }

    const { events } = readJournalEvents(this.journalPath);
    const projected = projectEventsToRecords(events);

    this.index.clear();
    this.fingerprintIndex.clear();
    this.highestId = 0;

    for (const [id, record] of projected.entries()) {
      this.index.set(id, record);
      
      if (record.fingerprint) {
        if (!this.fingerprintIndex.has(record.fingerprint)) {
          this.fingerprintIndex.set(record.fingerprint, []);
        }
        this.fingerprintIndex.get(record.fingerprint).push(record);
      }

      const numId = Number.parseInt(id, 10);
      if (!Number.isNaN(numId) && numId > this.highestId) {
        this.highestId = numId;
      }
    }

    this.writeProjectedRecordsToDatabase();

    return {
      eventsReplayed: events.length,
      incidentsDerived: projected.size
    };
  }

  /**
   * Performs a 4-layer read-only integrity audit across journal, checkpoint, and projections.
   *
   * @returns {object} - Comprehensive integrity report
   */
  verifyIntegrity() {
    return verifyLedgerIntegrity(this.ledgerDir);
  }

  /**
   * Quarantines a corrupted file by moving it out of records/ into quarantine/
   *
   * @param {string} filePath
   * @param {string} filename
   * @param {string} reason
   */
  quarantineFile(filePath, filename, reason) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const quarantineName = `${timestamp}_${filename}`;
    const targetPath = path.join(this.quarantineDir, quarantineName);

    try {
      fs.renameSync(filePath, targetPath);
      this.quarantined.push({
        file: quarantineName,
        reason,
        quarantinedAt: new Date().toISOString()
      });
    } catch {
      // If rename fails, try delete to prevent infinite crash loops
      try {
        fs.unlinkSync(filePath);
      } catch {
        // Fallback failed
      }
    }
  }

  /**
   * Calculates the next unique sequential record ID.
   *
   * @returns {string}
   */
  getNextId() {
    const checkpoint = readCheckpoint(this.ledgerDir);
    if (checkpoint && typeof checkpoint.highestIncidentId === 'number') {
      return String(Math.max(this.highestId, checkpoint.highestIncidentId) + 1);
    }
    return String(this.highestId + 1);
  }

  /**
   * Finds all records with an exact matching fingerprint, supporting cross-version matching
   * between modern v2 (64 hex) and legacy v1 (16 hex) fingerprints.
   *
   * @param {string} fingerprint
   * @returns {Array<import('./record.js').IncidentRecord>}
   */
  findByFingerprint(fingerprint) {
    if (!fingerprint) return [];
    let list = this.fingerprintIndex.get(fingerprint);
    if (!list || list.length === 0) {
      // Cross-version fallback
      if (fingerprint.length === 64) {
        list = this.fingerprintIndex.get(fingerprint.slice(0, 16));
      } else if (fingerprint.length === 16) {
        const matches = [];
        for (const [key, records] of this.fingerprintIndex.entries()) {
          if (key.length === 64 && key.startsWith(fingerprint)) {
            matches.push(...records);
          }
        }
        if (matches.length > 0) {
          list = matches;
        }
      }
    }
    if (!list) return [];
    return [...list].sort((a, b) => Number(b.id) - Number(a.id));
  }

  /**
   * Finds observations matching a fingerprint with cross-version fallback.
   *
   * @param {string} fingerprint
   * @returns {Array<object>}
   */
  findObservationsByFingerprint(fingerprint) {
    if (!fingerprint || !this.obsFingerprintIndex) return [];
    let list = this.obsFingerprintIndex.get(fingerprint);
    if (!list || list.length === 0) {
      if (fingerprint.length === 64) {
        list = this.obsFingerprintIndex.get(fingerprint.slice(0, 16));
      } else if (fingerprint.length === 16) {
        const matches = [];
        for (const [key, records] of this.obsFingerprintIndex.entries()) {
          if (key.length === 64 && key.startsWith(fingerprint)) {
            matches.push(...records);
          }
        }
        if (matches.length > 0) {
          list = matches;
        }
      }
    }
    return list || [];
  }

  /**
   * Searches for a prior record that reached the RECOVERED / VERIFIED state with the same fingerprint.
   *
   * @param {string} fingerprint
   * @returns {import('./record.js').IncidentRecord|null}
   */
  findVerifiedByFingerprint(fingerprint) {
    if (!fingerprint) return null;
    const list = this.findByFingerprint(fingerprint);
    if (!list || list.length === 0) return null;
    let latestVerified = null;

    for (const record of list) {
      const isRecovered = record.status === IncidentStatus.RECOVERED || record.status === 'VERIFIED';
      if (isRecovered) {
        if (!latestVerified || Number(record.id) > Number(latestVerified.id)) {
          latestVerified = record;
        }
      }
    }
    return latestVerified;
  }

  /**
   * Saves a command capture result as an immutable event in the authoritative journal,
   * updates the trusted checkpoint, and writes derived projection files.
   *
   * @param {import('../capture.js').CaptureRecord} captureResult
   * @param {object} [options]
   * @returns {import('./record.js').IncidentRecord}
   */
  saveRecord(captureResult, options = {}) {
    if (!this.initialized) {
      this.init();
    }

    const cleanCapture = redactRecordForStorage(captureResult);

    // Check for regression against previously verified records
    let initialState = options.initialState;
    let regressionOf = options.regressionOf || null;

    const computed = computeFingerprint({
      command: cleanCapture.command || '',
      args: cleanCapture.args || [],
      exitCode: cleanCapture.exitCode,
      signal: cleanCapture.signal,
      stderr: cleanCapture.stderr || '',
      stdout: cleanCapture.stdout || ''
    });
    const fingerprint = cleanCapture.fingerprint || computed.fingerprint;
    const normalizedError = cleanCapture.normalizedError || computed.normalizedError;

    if (cleanCapture.success) {
      return null;
    }

    if (!cleanCapture.success && !initialState) {
      const priorVerified = this.findVerifiedByFingerprint(fingerprint);
      if (priorVerified) {
        initialState = IncidentStatus.REGRESSED;
        regressionOf = priorVerified.id;
      } else {
        initialState = IncidentStatus.OBSERVED;
      }
    }

    // Process heavy evidence: save to isolated evidence store and bound output
    const rawStderr = cleanCapture.stderr || '';
    const rawStdout = cleanCapture.stdout || '';
    const fullOutput = rawStdout + (rawStdout && rawStderr ? '\n' : '') + rawStderr;

    const { evidenceHash, evidenceRef } = saveEvidenceArtifact(this.ledgerDir, fullOutput);
    const boundStderr = boundOutput(rawStderr);
    const boundStdout = boundOutput(rawStdout);
    const isTruncated = boundStderr.truncated || boundStdout.truncated;

    const eventType = initialState === IncidentStatus.REGRESSED ? 'regression.detected' : 'failure.observed';

    // Append to authoritative journal (with exclusive lock, fsync, and checkpoint update)
    const event = appendJournalEvent(this.ledgerDir, {
      type: eventType,
      incidentId: 'AUTO',
      payload: {
        command: cleanCapture.command || '',
        args: Array.isArray(cleanCapture.args) ? cleanCapture.args : [],
        fullCommand: cleanCapture.fullCommand || `${cleanCapture.command || ''} ${(cleanCapture.args || []).join(' ')}`.trim(),
        cwd: cleanCapture.cwd || '',
        durationMs: typeof cleanCapture.durationMs === 'number' ? cleanCapture.durationMs : 0,
        exitCode: typeof cleanCapture.exitCode === 'number' ? cleanCapture.exitCode : 1,
        signal: cleanCapture.signal || null,
        fingerprint: fingerprint || '',
        fingerprintVersion: inferFingerprintVersion(fingerprint, cleanCapture.fingerprintVersion || computed.fingerprintVersion),
        normalizedError: normalizedError || '',
        evidenceHash: evidenceHash || '',
        evidenceRef: evidenceRef || '',
        stderrSnippet: boundStderr.bounded || '',
        stdoutSnippet: boundStdout.bounded || '',
        isTruncated: Boolean(isTruncated),
        diagnostic: cleanCapture.diagnostic || null,
        environment: cleanCapture.environment || {},
        git: cleanCapture.git || { isGit: false },
        regressionOf: regressionOf || null
      }
    });

    const id = event.incidentId;
    this.highestId = Math.max(this.highestId, Number.parseInt(id, 10) || 0);

    // Incrementally apply the event in O(1) and write single projected record
    const record = this.applyJournalEvent(event, { syncDisk: true });

    // Link any existing unpromoted observations with this fingerprint
    if (fingerprint && this.obsFingerprintIndex) {
      const matchingObs = this.findObservationsByFingerprint(fingerprint);
      if (matchingObs) {
        for (const obs of matchingObs) {
          if (!obs.promotedToIncident) {
            obs.promotedToIncident = id;
            if (this.updateObsPromotedStmt) {
              this.updateObsPromotedStmt.run(id, JSON.stringify(obs), obs.id);
            }
          }
        }
      }
    }

    return record || this.index.get(id);
  }

  /**
   * Saves a lightweight failure observation (tier: OBSERVE) into the journal
   * and SQLite projection, with automatic TTL expiry.
   *
   * @param {import('../capture.js').CaptureRecord} captureResult
   * @param {object} [options]
   * @param {number} [options.ttlMs] TTL in milliseconds (default: 7 days)
   * @returns {object} The created observation record
   */
  saveObservation(captureResult, options = {}) {
    if (!this.initialized) {
      this.init();
    }

    const computed = computeFingerprint({
      command: captureResult.command || '',
      args: captureResult.args || [],
      exitCode: captureResult.exitCode,
      signal: captureResult.signal,
      stderr: captureResult.stderr || '',
      stdout: captureResult.stdout || ''
    });
    const fingerprint = captureResult.fingerprint || computed.fingerprint;
    const normalizedError = captureResult.normalizedError || computed.normalizedError;

    const obsId = `obs_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    const createdAt = new Date().toISOString();
    const ttlMs = options.ttlMs || (7 * 24 * 60 * 60 * 1000); // 7 days default
    const ttlExpiry = new Date(Date.now() + ttlMs).toISOString();

    const rawStderr = captureResult.stderr || '';
    const rawStdout = captureResult.stdout || '';
    const boundStderr = boundOutput(rawStderr);
    const boundStdout = boundOutput(rawStdout);

    const payload = {
      id: obsId,
      fingerprint,
      fingerprintVersion: inferFingerprintVersion(fingerprint, captureResult.fingerprintVersion || computed.fingerprintVersion),
      normalizedError: normalizedError || '',
      command: captureResult.command || '',
      args: Array.isArray(captureResult.args) ? captureResult.args : [],
      fullCommand: captureResult.fullCommand || `${captureResult.command || ''} ${(captureResult.args || []).join(' ')}`.trim(),
      cwd: captureResult.cwd || '',
      durationMs: typeof captureResult.durationMs === 'number' ? captureResult.durationMs : 0,
      exitCode: typeof captureResult.exitCode === 'number' ? captureResult.exitCode : 1,
      signal: captureResult.signal || null,
      stderr: boundStderr.bounded || '',
      stdout: boundStdout.bounded || '',
      diagnostic: captureResult.diagnostic || null,
      diagnosticType: captureResult.diagnostic?.errorType || null,
      createdAt,
      ttlExpiry,
      promotedToIncident: null,
      environment: captureResult.environment || {},
      git: captureResult.git || { isGit: false }
    };

    const event = appendJournalEvent(this.ledgerDir, {
      type: 'observation.recorded',
      incidentId: obsId,
      payload
    });

    const obs = { ...payload, _sequence: event.sequence };
    this.observations.set(obsId, obs);

    let list = this.obsFingerprintIndex.get(fingerprint);
    if (!list) {
      list = [];
      this.obsFingerprintIndex.set(fingerprint, list);
    }
    list.push(obs);

    if (this.insertObsStmt) {
      this.insertObsStmt.run(
        obsId,
        fingerprint,
        obs.command,
        obs.exitCode,
        obs.stderr,
        obs.diagnosticType,
        createdAt,
        null,
        ttlExpiry,
        JSON.stringify(obs)
      );
    }

    return obs;
  }

  /**
   * Retrieves an observation record by ID.
   *
   * @param {string} id
   * @returns {object|null}
   */
  getObservation(id) {
    if (!id) return null;
    return this.observations.get(String(id)) || null;
  }

  /**
   * Lists observations, optionally filtered by fingerprint or promotion status.
   *
   * @param {object} [options]
   * @param {string} [options.fingerprint]
   * @param {boolean} [options.unpromotedOnly]
   * @param {number} [options.limit]
   * @returns {Array<object>}
   */
  listObservations(options = {}) {
    let results = Array.from(this.observations.values());
    if (options.fingerprint) {
      results = results.filter(o => o.fingerprint === options.fingerprint);
    }
    if (options.unpromotedOnly) {
      results = results.filter(o => !o.promotedToIncident);
    }
    results.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
    if (typeof options.limit === 'number' && options.limit > 0) {
      results = results.slice(0, options.limit);
    }
    return results;
  }

  /**
   * Evaluates whether an incoming failure with this fingerprint should be promoted.
   * Promotes if:
   * 1. Matches an existing incident in the ledger (known failure recurring).
   * 2. Has prior unpromoted observation within window (default: 30 minutes).
   *
   * @param {string} fingerprint
   * @param {object} [options]
   * @param {number} [options.windowMs=1800000]
   * @returns {boolean}
   */
  shouldPromoteObservation(fingerprint, options = {}) {
    if (!fingerprint) return false;

    // 1. Matches existing incident in the ledger
    if (this.findByFingerprint(fingerprint).length > 0) {
      return true;
    }

    // 2. Has prior unpromoted observation within window
    const windowMs = typeof options.windowMs === 'number' ? options.windowMs : 30 * 60 * 1000;
    const cutoff = Date.now() - windowMs;

    const obsList = this.findObservationsByFingerprint(fingerprint);
    const recentUnpromoted = obsList.filter(obs => {
      if (obs.promotedToIncident) return false;
      const createdTime = new Date(obs.createdAt).getTime();
      return createdTime >= cutoff;
    });

    return recentUnpromoted.length >= 1;
  }

  /**
   * Promotes an observation to a full durable incident record.
   *
   * @param {string} observationId
   * @param {object} [options]
   * @returns {import('./record.js').IncidentRecord|null}
   */
  promoteObservation(observationId, options = {}) {
    if (!this.initialized) {
      this.init();
    }

    const obs = this.getObservation(observationId);
    if (!obs) return null;

    if (obs.promotedToIncident) {
      return this.getRecord(obs.promotedToIncident);
    }

    const rawStderr = obs.stderr || '';
    const rawStdout = obs.stdout || '';
    const fullOutput = rawStdout + (rawStdout && rawStderr ? '\n' : '') + rawStderr;
    const { evidenceHash, evidenceRef } = saveEvidenceArtifact(this.ledgerDir, fullOutput);

    const payload = {
      observationId: obs.id,
      command: obs.command,
      args: obs.args || [],
      fullCommand: obs.fullCommand,
      cwd: obs.cwd,
      durationMs: obs.durationMs,
      exitCode: obs.exitCode,
      signal: obs.signal,
      fingerprint: obs.fingerprint,
      fingerprintVersion: inferFingerprintVersion(obs.fingerprint, obs.fingerprintVersion),
      normalizedError: obs.normalizedError,
      evidenceHash,
      evidenceRef,
      stderrSnippet: obs.stderr,
      stdoutSnippet: obs.stdout,
      diagnostic: obs.diagnostic,
      environment: obs.environment,
      git: obs.git
    };

    const event = appendJournalEvent(this.ledgerDir, {
      type: 'observation.promoted',
      incidentId: 'AUTO',
      payload
    });

    const id = event.incidentId;
    this.highestId = Math.max(this.highestId, Number.parseInt(id, 10) || 0);

    const incident = this.applyJournalEvent(event, { syncDisk: true });

    // Mark observation as promoted
    obs.promotedToIncident = id;
    if (this.updateObsPromotedStmt) {
      this.updateObsPromotedStmt.run(id, JSON.stringify(obs), obs.id);
    }

    return incident || this.index.get(id);
  }

  /**
   * Cleans up expired observations based on ttlExpiry.
   *
   * @param {string} [nowIso]
   * @returns {number} Count of deleted observations
   */
  cleanupExpiredObservations(nowIso = new Date().toISOString()) {
    let deletedCount = 0;

    if (this.deleteExpiredObsStmt) {
      try {
        const info = this.deleteExpiredObsStmt.run(nowIso);
        deletedCount = info.changes || 0;
      } catch {}
    }

    // Clean in-memory
    const nowTime = new Date(nowIso).getTime();
    for (const [id, obs] of this.observations.entries()) {
      if (!obs.promotedToIncident && obs.ttlExpiry) {
        if (new Date(obs.ttlExpiry).getTime() <= nowTime) {
          this.observations.delete(id);
          const list = this.obsFingerprintIndex.get(obs.fingerprint);
          if (list) {
            const idx = list.findIndex(o => o.id === id);
            if (idx !== -1) list.splice(idx, 1);
          }
        }
      }
    }

    return deletedCount;
  }

  /**
   * Appends a new recovery attempt event to the authoritative journal and updates derived state.
   *
   * @param {string|number} id
   * @param {object} attemptData
   * @param {string|null} [attemptData.cause]
   * @param {string|null} [attemptData.change]
   * @param {string|null} [attemptData.verifyCmd]
   * @returns {import('./record.js').IncidentRecord}
   */
  addRecoveryAttempt(id, attemptData) {
    if (!this.initialized) {
      this.init();
    }

    const strId = normalizeId(id);
    const existing = this.getRecord(strId);
    if (!existing) {
      throw new CliError(`Incident #${strId} not found in ledger.`, {
        code: 'ERR_NOT_FOUND',
        exitCode: 1,
        details: { id: strId, suggestion: 'Run "rewind history" to browse all past incidents.' }
      });
    }

    const currentAttempts = Array.isArray(existing.recoveryAttempts) ? existing.recoveryAttempts : [];
    const attemptId = currentAttempts.length + 1;
    const isFixed = Boolean(attemptData.isFixed || attemptData.status === RecoveryAttemptStatus.FIXED);
    const initialStatus = isFixed ? RecoveryAttemptStatus.FIXED : RecoveryAttemptStatus.PROPOSED;
    const quality = isFixed
      ? EvidenceQuality.UNVERIFIED
      : (attemptData.change ? EvidenceQuality.USER_REPORTED : EvidenceQuality.UNVERIFIED);

    let verifyCmd = attemptData.verifyCmd || null;
    if (verifyCmd) {
      const vCmd = String(verifyCmd).trim();
      if (vCmd.length > 500) {
        throw new UsageError('Verification command exceeds maximum allowed length of 500 characters.');
      }
      if (/[\x00-\x08\x0B\x0C\x0E-\x1F]/.test(vCmd)) {
        throw new UsageError('Verification command contains invalid control characters.');
      }
      if (isTrivialVerifyCommand(vCmd)) {
        throw new UsageError(`Verification command "${vCmd}" is trivial and cannot empirically prove a fix.`);
      }
      verifyCmd = vCmd;
    }

    const source = attemptData.source || 'cli';

    // Append recovery.proposed event to authoritative journal
    const event = appendJournalEvent(this.ledgerDir, {
      type: 'recovery.proposed',
      incidentId: strId,
      payload: {
        attemptId,
        cause: attemptData.cause || null,
        causeProvenance: attemptData.cause ? (attemptData.causeProvenance || ProvenanceType.USER_REPORTED) : null,
        change: attemptData.change || null,
        changeProvenance: attemptData.change ? (attemptData.changeProvenance || ProvenanceType.USER_REPORTED) : null,
        verifyCmd,
        verifyCmdProvenance: verifyCmd ? (attemptData.verifyCmdProvenance || ProvenanceType.USER_REPORTED) : null,
        isFixed,
        status: attemptData.status || initialStatus,
        isExternal: Boolean(attemptData.isExternal),
        externalVerification: attemptData.externalVerification || null,
        observedChanges: attemptData.observedChanges || null,
        evidenceQuality: attemptData.evidenceQuality || quality,
        source,
        baselineFailed: Boolean(attemptData.baselineFailed)
      }
    });

    // Incrementally apply the event in O(1) and write single projected record
    return this.applyJournalEvent(event, { syncDisk: true }) || this.getRecord(strId);
  }


  /**
   * Records a verification execution run on a specific recovery attempt in the authoritative journal.
   *
   * @param {string|number} id
   * @param {number} attemptId
   * @param {object} runData
   * @param {string} runData.command
   * @param {number} runData.exitCode
   * @param {number} runData.durationMs
   * @param {string} runData.output
   * @param {string} [runData.environmentFingerprint]
   * @returns {import('./record.js').IncidentRecord}
   */
  recordVerificationRun(id, attemptId, runData) {
    if (!this.initialized) {
      this.init();
    }

    const strId = normalizeId(id);
    const existing = this.getRecord(strId);
    if (!existing) {
      throw new CliError(`Incident #${strId} not found in ledger.`, {
        code: 'ERR_NOT_FOUND',
        exitCode: 1,
        details: { id: strId, suggestion: 'Run "rewind history" to browse all past incidents.' }
      });
    }

    const currentAttempts = Array.isArray(existing.recoveryAttempts) ? existing.recoveryAttempts : [];
    const targetAttempt = currentAttempts.find(a => String(a.id) === String(attemptId));
    if (!targetAttempt) {
      throw new CliError(`Attempt #${attemptId} not found in Incident #${strId}.`);
    }

    const currentRuns = Array.isArray(targetAttempt.verificationRuns) ? targetAttempt.verificationRuns : [];
    const runId = currentRuns.length + 1;
    const isPassed = runData.exitCode === 0;
    const outputContent = runData.output || '';
    const outputHash = crypto.createHash('sha256').update(outputContent, 'utf8').digest('hex');

    const envSnapshot = runData.environment || (existing.environment && Object.keys(existing.environment).length > 0 ? existing.environment : captureSafeEnvironment());
    const gitSnapshot = runData.git || (existing.git && existing.git.isGit !== undefined ? existing.git : readGitMetadata(path.dirname(this.ledgerDir)));
    const envFingerprint = runData.environmentFingerprint || envSnapshot?.fingerprint || existing.environment?.fingerprint || '';

    // Append verification.run event to authoritative journal
    const event = appendJournalEvent(this.ledgerDir, {
      type: 'verification.run',
      incidentId: strId,
      payload: {
        attemptId,
        runId,
        command: runData.command || targetAttempt.verifyCmd || existing.command || '',
        exitCode: runData.exitCode,
        durationMs: runData.durationMs || 0,
        output: outputContent,
        outputHash,
        environment: envSnapshot,
        git: gitSnapshot,
        environmentFingerprint: envFingerprint,
        result: isPassed ? 'PASSED' : 'FAILED',
        provenance: ProvenanceType.DIRECTLY_VERIFIED,
        evidenceQuality: EvidenceQuality.DIRECT
      }
    });

    // Incrementally apply the event in O(1) and write single projected record
    return this.applyJournalEvent(event, { syncDisk: true }) || this.getRecord(strId);
  }


  /**
   * Evaluates staleness of a historical record against the current environment.
   *
   * @param {string|number} id
   * @param {import('../environment.js').EnvironmentSnapshot} [currentEnv]
   * @param {import('../git.js').GitMetadata} [currentGit]
   * @returns {import('./staleness.js').StalenessEvaluation}
   */
  getStalenessReport(id, currentEnv, currentGit) {
    const record = this.getRecord(id);
    return evaluateStaleness(record, currentEnv, currentGit);
  }

  /**
   * Extracts all known failed recovery approaches across a failure family.
   *
   * @param {string} fingerprint
   * @returns {Array<import('./negative_memory.js').FailedApproach>}
   */
  getNegativeMemory(fingerprint) {
    const familyRecords = this.findByFingerprint(fingerprint);
    return extractNegativeMemory(familyRecords);
  }

  /**
   * Analyzes contradictory or divergent verification evidence across a failure family.
   *
   * @param {string} fingerprint
   * @returns {import('./contradiction.js').ConflictReport}
   */
  getContradictionReport(fingerprint) {
    const familyRecords = this.findByFingerprint(fingerprint);
    return analyzeEvidenceConflicts(fingerprint, familyRecords);
  }

  /**
   * Evaluates historical recovery candidates and returns an actionable surfacing decision
   * (SURFACE, CAUTION, or SILENCE) applying strict abstention on stale/contradicted fixes.
   *
   * @param {import('./record.js').IncidentRecord|object} currentRecord
   * @returns {import('./surfacing.js').SurfacingDecision}
   */
  getSurfacingDecision(currentRecord) {
    if (!this.initialized) {
      this.init();
    }
    return evaluateSurfacing(currentRecord, this);
  }

  /**
   * Retrieves an incident record by ID.
   *
   * @param {string|number} id
   * @returns {import('./record.js').IncidentRecord|null}
   */
  getRecord(id) {
    if (!this.initialized) {
      this.init();
    }
    const strId = normalizeId(id);
    return this.index.get(strId) || null;
  }

  /**
   * Returns active incident records. Supports bounded querying and reverse order.
   *
   * @param {object} [options={}]
   * @param {number} [options.limit]
   * @param {number} [options.offset]
   * @param {boolean} [options.reverse=false]
   * @returns {{ records: Array<import('./record.js').IncidentRecord>, total: number }}
   */
  listRecords(options = {}) {
    if (!this.initialized) {
      this.init();
    }

    const { limit, offset = 0, reverse = false } = options;
    const values = Array.from(this.index.values());
    const total = values.length;

    values.sort((a, b) => Number.parseInt(a.id, 10) - Number.parseInt(b.id, 10));

    if (reverse) {
      values.reverse();
    }

    if (typeof limit === 'number' && limit > 0) {
      return { records: values.slice(offset, offset + limit), total };
    }
    
    if (offset > 0) {
      return { records: values.slice(offset), total };
    }

    return { records: values, total };
  }

  /**
   * Generates a deterministic pattern intelligence report from the authoritative journal.
   *
   * @param {object} [options={}]
   * @param {string} [options.fingerprint]
   * @param {number} [options.limit]
   * @returns {object}
   */
  getPatternReport(options = {}) {
    if (!this.initialized) {
      this.init();
    }
    return analyzePatternsFromJournal(this.ledgerDir, options);
  }

  /**
   * Generates an Agent Context payload from the authoritative journal.
   *
   * @param {string|number} [targetIdOrLatest='latest']
   * @param {object} [options={}]
   * @returns {object}
   */
  getAgentContext(targetIdOrLatest = 'latest', options = {}) {
    if (!this.initialized) {
      this.init();
    }
    return buildAgentContext(this.ledgerDir, targetIdOrLatest, options);
  }

  /**
   * Returns list of currently quarantined files.
   *
   * @returns {Array<{ file: string, reason: string, quarantinedAt: string }>}
   */
  getQuarantined() {
    return this.quarantined;
  }

  /**
   * Runs the complete self-diagnostics suite across ledger integrity, storage, and runtime.
   *
   * @param {object} [config={}]
   * @param {object} [options={}]
   * @returns {object}
   */
  diagnoseHealth(config = {}, options = {}) {
    return runDoctorDiagnostics(this.ledgerDir, config, options);
  }

  /**
   * Executes a safe non-destructive repair on derived projections and temporary directories.
   *
   * @param {object} [config={}]
   * @param {object} [options={}]
   * @returns {object}
   */
  repairHealth(config = {}, options = {}) {
    return executeDoctorRepair(this.ledgerDir, config, options);
  }

  /**
   * Scrubs raw unredacted secrets from the historical journal and evidence files,
   * recomputes canonical event digests and the cryptographic SHA-256 hash chain,
   * updates the trusted checkpoint, and safely rebuilds projections.
   *
   * @param {object} [options={}]
   * @returns {{ scrubbedCount: number, totalEvents: number, headChainHash: string }}
   */
  scrubLedger(options = {}) {
    if (!this.initialized) {
      this.init();
    }
    const lockPath = path.join(this.ledgerDir, 'journal.lock');
    const lock = acquireJournalLock(lockPath);
    try {
      const { events } = readJournalEvents(this.journalPath);
      if (events.length === 0) {
        return { scrubbedCount: 0, totalEvents: 0, headChainHash: GENESIS_HASH };
      }

      let scrubbedCount = 0;
      let prevHash = GENESIS_HASH;
      const scrubbedLines = [];

      for (let i = 0; i < events.length; i++) {
        const ev = events[i];
        const payload = ev.payload ? { ...ev.payload } : {};
        let modified = false;

        if (payload.command) {
          const redacted = redactSecrets(payload.command);
          if (redacted !== payload.command) { payload.command = redacted; modified = true; }
        }
        if (Array.isArray(payload.args)) {
          const redactedArgs = redactCommandArgs(payload.args);
          if (JSON.stringify(redactedArgs) !== JSON.stringify(payload.args)) {
            payload.args = redactedArgs;
            modified = true;
          }
        }
        if (payload.fullCommand) {
          const redacted = redactCommandString(payload.fullCommand);
          if (redacted !== payload.fullCommand) { payload.fullCommand = redacted; modified = true; }
        }
        if (payload.stdoutSnippet) {
          const redacted = redactSecrets(payload.stdoutSnippet);
          if (redacted !== payload.stdoutSnippet) { payload.stdoutSnippet = redacted; modified = true; }
        }
        if (payload.stderrSnippet) {
          const redacted = redactSecrets(payload.stderrSnippet);
          if (redacted !== payload.stderrSnippet) { payload.stderrSnippet = redacted; modified = true; }
        }
        if (payload.output) {
          const redacted = redactSecrets(payload.output);
          if (redacted !== payload.output) { payload.output = redacted; modified = true; }
        }

        if (modified) {
          scrubbedCount++;
        }

        const newSeq = i + 1;
        const scrubbedEvent = createEvent({
          type: ev.type,
          incidentId: ev.incidentId,
          payload,
          prevHash,
          sequence: newSeq
        });

        prevHash = scrubbedEvent.chainHash;
        scrubbedLines.push(canonicalStringify(scrubbedEvent));
      }

      // Also scrub evidence directory files if any
      if (fs.existsSync(this.evidenceDir)) {
        const evFiles = fs.readdirSync(this.evidenceDir);
        for (const f of evFiles) {
          if (!f.endsWith('.log')) continue;
          const fp = path.join(this.evidenceDir, f);
          try {
            const raw = fs.readFileSync(fp, 'utf8');
            const clean = redactSecrets(raw);
            if (clean !== raw) {
              fs.writeFileSync(fp, clean, 'utf8');
            }
          } catch {}
        }
      }

      // Write scrubbed journal atomically
      if (!fs.existsSync(this.tmpDir)) {
        fs.mkdirSync(this.tmpDir, { recursive: true, mode: 0o700 });
      }
      const tmpJournal = path.join(this.tmpDir, `journal_scrub_${Date.now()}.tmp`);
      fs.writeFileSync(tmpJournal, scrubbedLines.join('\n') + '\n', { mode: 0o600 });
      safeAtomicRenameSync(tmpJournal, this.journalPath);

      // Re-read checkpoint and write updated head
      const lastScrubbed = JSON.parse(scrubbedLines[scrubbedLines.length - 1]);
      writeCheckpoint(this.ledgerDir, {
        headSequence: lastScrubbed.sequence,
        headEventId: lastScrubbed.eventId,
        headChainHash: lastScrubbed.chainHash,
        eventCount: scrubbedLines.length,
        highestIncidentId: this.highestId
      });

      // Re-initialize DB and rebuild projections
      this.close();
      this.init();
      this.rebuildIndex({ syncDisk: true });

      return {
        scrubbedCount,
        totalEvents: events.length,
        headChainHash: lastScrubbed.chainHash
      };
    } finally {
      lock.release();
    }
  }
}
