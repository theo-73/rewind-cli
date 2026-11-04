import { redactSecrets, redactCommandArgs, redactCommandString, sanitizeForDisplay } from '../../sanitizer.js';
import { parseDiagnostic } from '../../diagnostics/index.js';
import { captureSafeEnvironment } from '../../environment.js';
import { readGitMetadata } from '../../git.js';
import { tokenizeCommandLine } from '../../parser.js';
import { Platform, EventType, CaptureOrigin, FailureKind, Outcome, createCanonicalExecution } from '../model.js';

/**
 * Normalizes a Claude Code hook payload (PostToolUseFailure or PreToolUse).
 *
 * @param {object} data - Parsed payload from Claude Code
 * @param {object} [contextOptions={}] - Additional context
 * @returns {import('../model.js').CanonicalExecution}
 */
export function normalizeClaudePayload(data = {}, contextOptions = {}) {
  const sessionId = data.session_id || data.sessionId || null;
  const toolName = data.tool_name || data.toolName || 'Bash';
  const input = data.tool_input || data.input || {};
  const rawCmd = (input.command || input.cmd || data.command || '').trim();
  const cwd = data.cwd || input.cwd || contextOptions.cwd || process.cwd();

  const isPreflight = contextOptions.eventType === EventType.PRE_TOOL_USE ||
    data.hookEventName === 'PreToolUse' ||
    data.eventType === 'PreToolUse';

  const eventType = isPreflight ? EventType.PRE_TOOL_USE : EventType.POST_TOOL_USE_FAILURE;
  const rawStderr = data.error || data.stderr || '';
  const rawStdout = data.stdout || '';
  const stderr = sanitizeForDisplay(redactSecrets(rawStderr));
  const stdout = sanitizeForDisplay(redactSecrets(rawStdout));
  const durationMs = typeof data.duration_ms === 'number' && data.duration_ms >= 0 ? data.duration_ms : 0;

  const isInterrupt = Boolean(data.is_interrupt);
  const exitCode = typeof data.exit_code === 'number' ? data.exit_code : (isInterrupt ? 130 : (isPreflight ? null : 1));

  let outcome = Outcome.UNKNOWN;
  let failureKind = FailureKind.UNKNOWN;

  if (isPreflight) {
    outcome = Outcome.UNKNOWN;
    failureKind = FailureKind.UNKNOWN;
  } else if (isInterrupt) {
    outcome = Outcome.INTERRUPTED;
    failureKind = FailureKind.INTERRUPTED;
  } else {
    outcome = Outcome.FAILURE;
    failureKind = FailureKind.EXECUTION_FAILURE;
  }

  const tokens = tokenizeCommandLine(rawCmd);
  const command = tokens[0] ? redactSecrets(tokens[0]) : redactSecrets(rawCmd);
  const args = redactCommandArgs(tokens.slice(1));
  const fullCommand = redactCommandString(rawCmd);

  const env = captureSafeEnvironment(process.env);
  const git = readGitMetadata(cwd);
  const diagnostic = !isPreflight ? parseDiagnostic(stderr, stdout, { command, cwd }) : null;

  return createCanonicalExecution({
    platform: Platform.CLAUDE,
    eventType,
    captureOrigin: CaptureOrigin.AGENT_EVENT,
    sessionId,
    toolName,
    command,
    args,
    fullCommand,
    cwd,
    durationMs,
    exitCode,
    outcome,
    failureKind,
    executionStarted: !isPreflight,
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
