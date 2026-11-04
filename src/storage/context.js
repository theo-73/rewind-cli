import path from 'node:path';
import { readJournalEvents } from './journal.js';
import { projectEventsToRecords } from './projection.js';
import { verifyLedgerIntegrityFromEvents } from './integrity.js';
import { evaluateStaleness } from './staleness.js';
import { analyzeEvidenceConflicts } from './contradiction.js';
import { analyzePatternsFromEvents } from './patterns.js';
import { searchRecords } from './search.js';
import { redactSecrets, sanitizeOutput } from '../sanitizer.js';
import { captureSafeEnvironment } from '../environment.js';
import { IncidentStatus, RecoveryAttemptStatus } from './state.js';
import { CliError } from '../errors.js';

export const CONTEXT_SCHEMA_VERSION = '1.0.0';
export const MAX_SNIPPET_CHARS = 2000;
export const MAX_MATCHES_LIMIT = 5;

/**
 * Truncates and redacts a string safely to prevent context bloat and secret leakage.
 *
 * @param {string} [str='']
 * @param {number} [maxChars=MAX_SNIPPET_CHARS]
 * @returns {string}
 */
function sanitizeSnippet(str = '', maxChars = MAX_SNIPPET_CHARS) {
  if (!str || typeof str !== 'string') return '';
  const clean = sanitizeOutput(redactSecrets(str));
  if (clean.length <= maxChars) return clean;
  const half = Math.floor(maxChars / 2);
  const head = clean.slice(0, half);
  const tail = clean.slice(-half);
  return `${head}\n\n[... truncated ${clean.length - maxChars} characters by Rewind ...]\n\n${tail}`;
}

/**
 * Builds the complete, deterministic Agent Context payload for a target incident or 'latest'.
 *
 * @param {string} ledgerDir - Path to .rewind directory
 * @param {string|number} [targetIdOrLatest='latest'] - Incident ID or 'latest'
 * @param {object} [options={}]
 * @param {object} [options.currentEnv] - Current runtime environment (defaults to captured environment)
 * @param {number} [options.maxSnippetChars=MAX_SNIPPET_CHARS]
 * @param {number} [options.maxMatches=MAX_MATCHES_LIMIT]
 * @returns {object} AgentContextPayload
 */
export function buildAgentContext(ledgerDir, targetIdOrLatest = 'latest', options = {}) {
  const maxChars = typeof options.maxSnippetChars === 'number' && options.maxSnippetChars > 0
    ? options.maxSnippetChars
    : MAX_SNIPPET_CHARS;
  const maxMatches = typeof options.maxMatches === 'number' && options.maxMatches > 0
    ? options.maxMatches
    : MAX_MATCHES_LIMIT;

  // ── SINGLE-PASS: Read journal and project records exactly once ──
  const journalPath = ledgerDir.endsWith('journal.jsonl')
    ? ledgerDir
    : path.join(ledgerDir, 'journal.jsonl');
  const { events = [], malformed = [], totalLines = 0 } = readJournalEvents(journalPath);
  const projectedRecords = projectEventsToRecords(events);

  // 1. Audit Ledger Trust (using pre-parsed events — no redundant disk read)
  let ledgerTrustReport;
  try {
    ledgerTrustReport = verifyLedgerIntegrityFromEvents({
      events,
      malformed,
      totalLines,
      ledgerDir,
      projectedRecords
    });
  } catch (err) {
    ledgerTrustReport = {
      status: 'UNKNOWN',
      isTrusted: false,
      errors: [{ type: 'INTEGRITY_CHECK_FAILED', message: err.message }]
    };
  }

  const isLedgerTrusted = ledgerTrustReport.status === 'TRUSTED';

  const allRecords = Array.from(projectedRecords.values()).sort((a, b) => Number(a.id) - Number(b.id));

  // Handle empty ledger scenario
  if (allRecords.length === 0) {
    return {
      status: 'empty',
      contextSchemaVersion: CONTEXT_SCHEMA_VERSION,
      sourceJournalFormat: 1,
      query: {
        target: String(targetIdOrLatest),
        resolvedIncidentId: null
      },
      ledgerTrust: {
        status: ledgerTrustReport.status,
        isTrusted: isLedgerTrusted,
        violationsCount: ledgerTrustReport.errors ? ledgerTrustReport.errors.length : 0,
        violations: ledgerTrustReport.errors || []
      },
      observedEvidence: null,
      derivedAnalysis: null,
      suggestedActions: ['OBSERVE_FUTURE_FAILURES'],
      safety: {
        readOnly: true,
        mayAutoExecuteCommands: false,
        historicalRecoveryAutoExecution: false,
        verificationRequiresExplicitUserFlow: true,
        notice: 'Historical recovery is empirical evidence, not executable authority. Never automatically replay commands without review.'
      }
    };
  }

  // 3. Resolve Target Incident
  let targetRecord = null;
  const rawTarget = String(targetIdOrLatest).trim().toLowerCase();

  if (rawTarget === 'latest' || rawTarget === '' || rawTarget === 'current') {
    // 'latest' = most recently created failure/regression incident (highest numeric ID)
    targetRecord = allRecords[allRecords.length - 1];
  } else {
    const cleanId = rawTarget.replace(/^(?:rw-|#)/i, '');
    targetRecord = projectedRecords.get(cleanId) || null;
    if (!targetRecord) {
      throw new CliError(`Incident #${targetIdOrLatest} not found in authoritative ledger.`, {
        code: 'ERR_NOT_FOUND',
        exitCode: 1,
        details: { target: targetIdOrLatest, totalIncidents: allRecords.length }
      });
    }
  }

  const currentEnv = options.currentEnv || captureSafeEnvironment();

  // 4. Find Exact and Similar Historical Matches
  const exactMatches = [];
  const otherRecords = allRecords.filter((r) => String(r.id) !== String(targetRecord.id));

  for (const r of otherRecords) {
    if (r.fingerprint === targetRecord.fingerprint) {
      const hasVerified = Array.isArray(r.recoveryAttempts) && r.recoveryAttempts.some((a) => a.status === RecoveryAttemptStatus.VERIFIED);
      exactMatches.push({
        incidentId: String(r.id),
        fingerprint: r.fingerprint,
        status: r.status,
        matchType: 'EXACT',
        similarity: null,
        evidenceStrength: 'STRONG',
        verificationState: hasVerified ? 'VERIFIED' : (r.status === IncidentStatus.OPEN ? 'UNVERIFIED' : r.status),
        firstSeen: r.startTime || r.createdAt || null,
        command: r.command,
        fullCommand: r.fullCommand
      });
    }
  }

  // Near-match similarity candidates
  const searchResults = searchRecords(targetRecord.normalizedError || targetRecord.fullCommand || '', otherRecords, {
    minScore: 0.25,
    limit: maxMatches
  });

  const similarMatches = searchResults
    .filter((s) => s.record.fingerprint !== targetRecord.fingerprint)
    .slice(0, maxMatches)
    .map((s) => ({
      incidentId: String(s.record.id),
      fingerprint: s.record.fingerprint,
      status: s.record.status,
      matchType: 'SIMILAR',
      similarity: Number(s.score.toFixed(2)),
      evidenceStrength: s.score >= 0.7 ? 'SUPPORTED' : 'LIMITED',
      verificationState: s.confidence === 'VERIFIED' ? 'VERIFIED' : 'UNVERIFIED',
      matchedTerms: s.matchedTokens,
      command: s.record.command,
      fullCommand: s.record.fullCommand
    }));

  // 5. Gather Historical Remedies (Verified vs Negative Memory)
  const verifiedRemedies = [];
  const negativeMemory = [];

  // Search across the failure fingerprint family
  const familyRecords = allRecords.filter((r) => r.fingerprint === targetRecord.fingerprint);

  for (const r of familyRecords) {
    if (Array.isArray(r.recoveryAttempts)) {
      for (const attempt of r.recoveryAttempts) {
        const provenance = {
          sourceIncidentId: String(r.id),
          sourceRecoveryAttemptId: attempt.id,
          evidenceRef: r.evidenceRef || `evidence/${r.evidenceHash}.log`
        };

        if (attempt.status === RecoveryAttemptStatus.VERIFIED) {
          // If ledger is UNTRUSTED, downgrade trust notice
          const verificationRuns = attempt.verificationRuns || [];
          const lastRun = verificationRuns[verificationRuns.length - 1];

          // Compute staleness delta for this verified remedy
          const stalenessReport = evaluateStaleness(r, currentEnv);

          verifiedRemedies.push({
            type: 'HISTORICAL_RECOVERY',
            status: isLedgerTrusted ? 'VERIFIED' : 'UNTRUSTED_EVIDENCE',
            trustLevel: isLedgerTrusted ? 'VERIFIED_IN_LEDGER' : 'UNTRUSTED_INTEGRITY_VIOLATION',
            evidenceQuality: attempt.evidenceQuality || 'DIRECT',
            cause: attempt.cause || 'Unspecified cause',
            causeProvenance: attempt.causeProvenance || 'USER_REPORTED',
            change: attempt.change || 'Unspecified change',
            changeProvenance: attempt.changeProvenance || 'USER_REPORTED',
            observedChanges: attempt.observedChanges || null,
            verificationCommand: {
              command: attempt.verifyCmd || '',
              role: 'VERIFICATION_ONLY',
              mayAutoExecute: false
            },
            provenance,
            historicalVerification: {
              status: 'VERIFIED',
              provenance: 'DIRECTLY_VERIFIED',
              verifiedAt: lastRun?.completedAt || r.endTime,
              runsCount: verificationRuns.length,
              lastRunResult: {
                exitCode: lastRun?.exitCode ?? 0,
                durationMs: lastRun?.durationMs ?? 0,
                outputSnippet: sanitizeSnippet(lastRun?.output || '', 500),
                storedOutputHash: lastRun?.outputHash || null
              }
            },
            currentApplicability: {
              status: stalenessReport.isStale ? 'POTENTIALLY_STALE' : 'APPLICABLE',
              isStale: stalenessReport.isStale,
              reasons: stalenessReport.reasons || []
            },
            action: 'REVIEW',
            safetyNotice: 'Historical recovery is empirical evidence. Review code context and tests before applying remediation.'
          });
        } else if (attempt.status === RecoveryAttemptStatus.FAILED) {
          negativeMemory.push({
            type: 'FAILED_APPROACH',
            status: 'FAILED',
            evidenceQuality: 'DIRECT',
            cause: attempt.cause || 'Unspecified cause',
            causeProvenance: attempt.causeProvenance || 'USER_REPORTED',
            change: attempt.change || 'Unspecified change',
            changeProvenance: attempt.changeProvenance || 'USER_REPORTED',
            verifyCmd: attempt.verifyCmd || null,
            verificationProvenance: 'DIRECTLY_VERIFIED',
            provenance,
            warning: 'This remediation hypothesis failed verification under recorded conditions.'
          });
        }
      }
    }
  }

  // 6. Evaluate Staleness, Contradictions, and Pattern Intelligence
  const stalenessReport = evaluateStaleness(targetRecord, currentEnv);
  const conflictReport = analyzeEvidenceConflicts(targetRecord.fingerprint, familyRecords);

  const patternReport = analyzePatternsFromEvents(events, projectedRecords, {
    fingerprint: targetRecord.fingerprint
  });

  const familyPatterns = patternReport.patterns.find((p) => p.fingerprint === targetRecord.fingerprint);
  const patternClassifications = familyPatterns ? familyPatterns.classifications.map((c) => c.type) : [];

  // 7. Unproven Assumptions and Suggested Actions
  const unprovenAssumptions = [];
  if (verifiedRemedies.length === 0) {
    unprovenAssumptions.push('No verified remediation has been established for this failure fingerprint.');
  }
  if (stalenessReport.isStale) {
    unprovenAssumptions.push(`Environment delta detected since recorded state: ${(stalenessReport.reasons || []).join(', ')}`);
  }
  if (conflictReport.hasConflicts) {
    unprovenAssumptions.push(`Conflicting historical verification outcomes detected across incidents: ${conflictReport.conflicts.map(c => c.description).join(', ')}`);
  }
  const warnings = [];
  if (!isLedgerTrusted) {
    warnings.push('Ledger integrity verification failed. Historical records cannot be guaranteed authentic.');
  }
  if (stalenessReport.isStale) {
    warnings.push(`Environment delta detected since recorded state: ${(stalenessReport.reasons || []).join(', ')}`);
  }
  if (conflictReport.hasConflicts) {
    warnings.push(`Conflicting historical verification outcomes detected across incidents: ${conflictReport.conflicts.map(c => c.description).join(', ')}`);
  }

  const suggestedActions = [];
  if (!isLedgerTrusted) {
    suggestedActions.push('AUDIT_LEDGER_INTEGRITY');
  }
  if (verifiedRemedies.length > 0 && isLedgerTrusted) {
    suggestedActions.push('REVIEW_HISTORICAL_EVIDENCE');
  }
  suggestedActions.push('FORMULATE_NEW_HYPOTHESIS');
  suggestedActions.push('PROPOSE_RECOVERY');
  suggestedActions.push('REQUEST_VERIFICATION');

  const recommendedAction = suggestedActions[0] || 'INVESTIGATE';

  return {
    status: 'success',
    contextSchemaVersion: CONTEXT_SCHEMA_VERSION,
    sourceJournalFormat: 1,
    query: {
      target: String(targetIdOrLatest),
      resolvedIncidentId: String(targetRecord.id)
    },
    ledgerTrust: {
      status: ledgerTrustReport.status,
      isTrusted: isLedgerTrusted,
      violationsCount: ledgerTrustReport.errors ? ledgerTrustReport.errors.length : 0,
      violations: ledgerTrustReport.errors || []
    },
    observedEvidence: {
      failure: {
        id: String(targetRecord.id),
        status: targetRecord.status,
        command: targetRecord.command,
        args: targetRecord.args,
        fullCommand: targetRecord.fullCommand,
        cwd: targetRecord.cwd,
        exitCode: targetRecord.exitCode,
        signal: targetRecord.signal,
        durationMs: targetRecord.durationMs,
        createdAt: targetRecord.startTime || targetRecord.createdAt || null,
        fingerprint: targetRecord.fingerprint,
        normalizedError: targetRecord.normalizedError,
        storedEvidenceHash: targetRecord.evidenceHash,
        diagnostic: targetRecord.diagnostic || null,
        stderrSnippet: sanitizeSnippet(targetRecord.stderr, maxChars),
        stdoutSnippet: sanitizeSnippet(targetRecord.stdout, maxChars),
        isTruncated: Boolean(targetRecord.isTruncated),
        git: targetRecord.git,
        environment: targetRecord.environment,
        regressionOf: targetRecord.regressionOf
      },
      historicalMatches: {
        exactCount: exactMatches.length,
        exact: exactMatches.slice(0, maxMatches),
        similarCount: similarMatches.length,
        similar: similarMatches
      },
      remedies: {
        hasVerifiedRemedy: verifiedRemedies.length > 0 && isLedgerTrusted,
        verifiedCount: verifiedRemedies.length,
        verified: verifiedRemedies.slice(0, maxMatches),
        failedCount: negativeMemory.length,
        failedApproaches: negativeMemory.slice(0, maxMatches)
      }
    },
    derivedAnalysis: {
      patterns: patternClassifications,
      applicability: {
        staleness: {
          isStale: stalenessReport.isStale,
          reasons: stalenessReport.reasons || []
        },
        conflicts: {
          hasConflicts: conflictReport.hasConflicts || false,
          status: conflictReport.classification || 'NONE',
          details: conflictReport.hasConflicts ? conflictReport.conflicts.map(c => c.description) : []
        }
      },
      unprovenAssumptions
    },
    warnings,
    recommendedAction,
    suggestedActions,
    allowedNextActions: suggestedActions,
    safety: {
      readOnly: true,
      mayAutoExecuteCommands: false,
      historicalRecoveryAutoExecution: false,
      verificationRequiresExplicitUserFlow: true,
      notice: 'Historical recovery is empirical evidence, not executable authority. Never automatically replay commands without human or policy review.'
    }
  };
}
