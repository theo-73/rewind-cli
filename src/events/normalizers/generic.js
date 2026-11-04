import { redactSecrets, redactCommandArgs, redactCommandString, sanitizeForDisplay } from '../../sanitizer.js';
import { parseDiagnostic } from '../../diagnostics/index.js';
import { captureSafeEnvironment } from '../../environment.js';
import { readGitMetadata } from '../../git.js';
import { tokenizeCommandLine } from '../../parser.js';
import { Platform, EventType, CaptureOrigin, FailureKind, Outcome, createCanonicalExecution } from '../model.js';
import { normalizeCursorPayload } from './cursor.js';
import { normalizeGeminiPayload } from './gemini.js';
import { normalizeClaudePayload } from './claude.js';
import { normalizeCodexPayload } from './codex.js';

/**
 * Normalizes generic or unclassified event payloads.
 * Conservative auto-detection only triggers on unmistakable, compound signatures.
 * Invariant: `data.tool_input` alone will NEVER auto-infer Cursor.
 *
 * @param {object} data - Parsed JSON payload
 * @param {object} [contextOptions={}] - Additional context
 * @returns {import('../model.js').CanonicalExecution}
 */
export function normalizeGenericPayload(data = {}, contextOptions = {}) {
  // Conservative compound detection for known platforms without explicit source flag
  if (data.conversation_id && (data.tool_output || (data.tool_name && data.tool_input))) {
    return normalizeCursorPayload(data, contextOptions);
  }
  if ((data.session_id && (data.parameters || data.result || data.tool_response)) ||
      (data.hookSpecificOutput && data.hookSpecificOutput.hookEventName === 'AfterTool')) {
    return normalizeGeminiPayload(data, contextOptions);
  }
  if ((data.is_interrupt !== undefined && (data.tool_name || data.toolName)) ||
      data.hookEventName === 'PostToolUseFailure' ||
      data.hookEventName === 'PreToolUse') {
    return normalizeClaudePayload(data, contextOptions);
  }
  if (data.tool && data.input && data.output) {
    return normalizeCodexPayload(data, contextOptions);
  }

  // Pure generic execution
  const rawCmd = (data.command || data.cmd || data.rawText || '').trim();
  const cwd = data.cwd || contextOptions.cwd || process.cwd();
  const tokens = tokenizeCommandLine(rawCmd);
  const command = tokens[0] ? redactSecrets(tokens[0]) : redactSecrets(rawCmd);
  const args = redactCommandArgs(tokens.slice(1));
  const fullCommand = redactCommandString(rawCmd);

  let exitCode = null;
  if (typeof data.exitCode === 'number') {
    exitCode = data.exitCode;
  } else if (typeof data.exit_code === 'number') {
    exitCode = data.exit_code;
  }

  const rawStderr = data.stderr || data.error || (exitCode !== null && exitCode !== 0 ? data.rawText || '' : '');
  const rawStdout = data.stdout || '';
  const stderr = sanitizeForDisplay(redactSecrets(rawStderr));
  const stdout = sanitizeForDisplay(redactSecrets(rawStdout));
  const durationMs = typeof data.durationMs === 'number' ? data.durationMs : (typeof data.duration_ms === 'number' ? data.duration_ms : 0);

  const env = captureSafeEnvironment(process.env);
  const git = readGitMetadata(cwd);
  const diagnostic = parseDiagnostic(stderr, stdout, { command, cwd });

  let outcome = Outcome.UNKNOWN;
  if (exitCode === 0) outcome = Outcome.SUCCESS;
  else if (exitCode !== null && exitCode > 0) outcome = Outcome.FAILURE;
  else if (rawStderr) outcome = Outcome.FAILURE;

  let failureKind = FailureKind.UNKNOWN;
  if (exitCode !== null && exitCode > 0) failureKind = FailureKind.EXECUTION_FAILURE;
  if (data.timedOut) failureKind = FailureKind.TIMEOUT;

  return createCanonicalExecution({
    platform: Platform.GENERIC,
    eventType: EventType.COMMAND,
    captureOrigin: contextOptions.captureOrigin || CaptureOrigin.AGENT_EVENT,
    sessionId: data.sessionId || data.session_id || null,
    toolName: data.toolName || data.tool_name || null,
    command,
    args,
    fullCommand,
    cwd,
    durationMs,
    exitCode,
    outcome,
    failureKind,
    executionStarted: exitCode !== null || Boolean(rawStderr || rawStdout),
    timedOut: Boolean(data.timedOut),
    stdout,
    stderr,
    stdoutRaw: rawStdout,
    stderrRaw: rawStderr,
    diagnostic,
    environment: env,
    git
  });
}
