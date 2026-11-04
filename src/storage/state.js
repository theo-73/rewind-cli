import { UsageError } from '../errors.js';

/**
 * 1. Incident Status (Lifecycle of the Failure Incident)
 */
export const IncidentStatus = Object.freeze({
  OBSERVED: 'OBSERVED',     // Raw failure captured, awaiting hypothesis or remediation
  OPEN: 'OPEN',             // Active remediation/attempts in progress
  RECOVERED: 'RECOVERED',   // At least one recovery attempt succeeded and verified
  REGRESSED: 'REGRESSED',   // Recurrence of a previously verified failure fingerprint
  RESOLVED: 'RESOLVED'      // Explicitly closed / accepted solution
});

/**
 * 2. Recovery Attempt Status (Per-Remediation Lifecycle)
 * Strictly distinguishes user claims (FIXED) from empirical outcomes (VERIFIED).
 */
export const RecoveryAttemptStatus = Object.freeze({
  PROPOSED: 'PROPOSED',     // Cause hypothesis recorded or change described, awaiting application
  ATTEMPTED: 'ATTEMPTED',   // Verification initiated or remediation actively in progress
  FIXED: 'FIXED',           // User asserts that the change was applied, but unverified
  FAILED: 'FAILED',         // Verification failed with non-zero exit (Negative Memory)
  VERIFIED: 'VERIFIED'      // Explicit verification command passed (Exit 0)
});

/**
 * 3. Evidence Provenance Types (Distinguishes user assertions from automated empirical facts)
 */
export const ProvenanceType = Object.freeze({
  USER_REPORTED: 'USER_REPORTED',                   // User-provided statements, hypotheses, descriptions
  AUTOMATICALLY_OBSERVED: 'AUTOMATICALLY_OBSERVED', // Git status, file touches, process exit codes, timing, env
  DIRECTLY_VERIFIED: 'DIRECTLY_VERIFIED',           // Explicit verification execution run with recorded outcome
  INFERRED: 'INFERRED',                             // Derived patterns, similarity heuristics
  UNKNOWN: 'UNKNOWN'                                // Legacy or unclassified data
});

/**
 * 4. Evidence Quality Ratings (Communicates what Rewind actually knows without arbitrary numbers)
 */
export const EvidenceQuality = Object.freeze({
  DIRECT: 'DIRECT',               // Primary process capture or direct verification run
  SUPPORTED: 'SUPPORTED',         // Corroborated by verified historical proof
  USER_REPORTED: 'USER_REPORTED', // Unverified user statement
  INFERRED: 'INFERRED',           // Algorithmic heuristic or unverified pattern
  UNVERIFIED: 'UNVERIFIED'        // Fix proposed or marked FIXED without successful verification run
});

/**
 * 5. Proof Tiers (Red-to-Green Empirical Verification Strength)
 * Distinguishes genuine empirical fixes from tautological passes or unverified claims.
 */
export const ProofTier = Object.freeze({
  PROVEN: 'PROVEN',             // Empirically verified: verified baseline failure (red) followed by pass (green)
  CLAIMED_PASS: 'CLAIMED_PASS', // Passed verify command without recorded baseline failure (could be tautology)
  UNPROVEN: 'UNPROVEN'          // Marked FIXED or PROPOSED without successful verification run
});

/**
 * Computes the empirical proof tier for a recovery attempt based on its verification runs.
 *
 * @param {object} attempt
 * @returns {string} ProofTier (PROVEN | CLAIMED_PASS | UNPROVEN)
 */
export function computeProofTier(attempt) {
  if (!attempt || typeof attempt !== 'object') return ProofTier.UNPROVEN;
  const runs = Array.isArray(attempt.verificationRuns) ? attempt.verificationRuns : [];
  if (runs.length === 0) {
    return ProofTier.UNPROVEN;
  }

  const hasPassed = runs.some((r) => r.result === 'PASSED' || r.exitCode === 0);
  if (!hasPassed) {
    return ProofTier.UNPROVEN;
  }

  // Check if a failure occurred prior to or as a baseline before a pass
  const firstPassIndex = runs.findIndex((r) => r.result === 'PASSED' || r.exitCode === 0);
  const hadPriorFailure = runs.slice(0, firstPassIndex).some(
    (r) => r.result === 'FAILED' || (typeof r.exitCode === 'number' && r.exitCode !== 0)
  );

  if (hadPriorFailure || attempt.baselineFailed) {
    return ProofTier.PROVEN;
  }

  return ProofTier.CLAIMED_PASS;
}



/**
 * Valid incident lifecycle state transitions.
 */
const VALID_INCIDENT_TRANSITIONS = {
  [IncidentStatus.OBSERVED]: new Set([
    IncidentStatus.OPEN,
    IncidentStatus.RESOLVED
  ]),
  [IncidentStatus.OPEN]: new Set([
    IncidentStatus.OPEN,
    IncidentStatus.RECOVERED,
    IncidentStatus.RESOLVED
  ]),
  [IncidentStatus.RECOVERED]: new Set([
    IncidentStatus.OPEN,
    IncidentStatus.RESOLVED
  ]),
  [IncidentStatus.REGRESSED]: new Set([
    IncidentStatus.OPEN,
    IncidentStatus.RECOVERED,
    IncidentStatus.RESOLVED
  ]),
  [IncidentStatus.RESOLVED]: new Set([
    IncidentStatus.OPEN
  ])
};

/**
 * Valid recovery attempt state transitions.
 */
const VALID_ATTEMPT_TRANSITIONS = {
  [RecoveryAttemptStatus.PROPOSED]: new Set([
    RecoveryAttemptStatus.PROPOSED,
    RecoveryAttemptStatus.ATTEMPTED,
    RecoveryAttemptStatus.FIXED,
    RecoveryAttemptStatus.FAILED,
    RecoveryAttemptStatus.VERIFIED
  ]),
  [RecoveryAttemptStatus.ATTEMPTED]: new Set([
    RecoveryAttemptStatus.FIXED,
    RecoveryAttemptStatus.FAILED,
    RecoveryAttemptStatus.VERIFIED
  ]),
  [RecoveryAttemptStatus.FIXED]: new Set([
    RecoveryAttemptStatus.ATTEMPTED,
    RecoveryAttemptStatus.FAILED,
    RecoveryAttemptStatus.VERIFIED
  ]),
  [RecoveryAttemptStatus.FAILED]: new Set([
    // Terminal state for a specific attempt (subsequent attempt created instead)
  ]),
  [RecoveryAttemptStatus.VERIFIED]: new Set([
    // Terminal state for a specific attempt
  ])
};

/**
 * Validates whether an incident state transition is legal.
 *
 * @param {string} fromState
 * @param {string} toState
 * @returns {boolean}
 */
export function isValidIncidentTransition(fromState, toState) {
  if (!fromState || !toState) return false;
  if (fromState === toState) return true;
  const allowed = VALID_INCIDENT_TRANSITIONS[fromState];
  return Boolean(allowed && allowed.has(toState));
}

/**
 * Asserts a valid incident state transition or throws UsageError.
 *
 * @param {string} fromState
 * @param {string} toState
 * @param {string} incidentId
 */
export function assertValidIncidentTransition(fromState, toState, incidentId) {
  if (!isValidIncidentTransition(fromState, toState)) {
    throw new UsageError(
      `Illegal incident state transition from "${fromState}" to "${toState}" for Incident #${incidentId}.`
    );
  }
}

/**
 * Validates whether a recovery attempt transition is legal.
 *
 * @param {string} fromState
 * @param {string} toState
 * @returns {boolean}
 */
export function isValidAttemptTransition(fromState, toState) {
  if (!fromState || !toState) return false;
  if (fromState === toState) return true;
  const allowed = VALID_ATTEMPT_TRANSITIONS[fromState];
  return Boolean(allowed && allowed.has(toState));
}

/**
 * Asserts a valid recovery attempt transition or throws UsageError.
 *
 * @param {string} fromState
 * @param {string} toState
 * @param {number|string} attemptId
 */
export function assertValidAttemptTransition(fromState, toState, attemptId) {
  if (!isValidAttemptTransition(fromState, toState)) {
    throw new UsageError(
      `Illegal recovery attempt state transition from "${fromState}" to "${toState}" for Attempt #${attemptId}.`
    );
  }
}

/**
 * Legacy compatibility alias for existing code.
 */
export function isValidTransition(fromState, toState) {
  return isValidIncidentTransition(fromState, toState);
}

/**
 * Legacy compatibility alias for existing code.
 */
export function assertValidTransition(fromState, toState, incidentId) {
  assertValidIncidentTransition(fromState, toState, incidentId);
}
