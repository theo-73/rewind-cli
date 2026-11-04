import { redactSecrets, redactCommandArgs, redactCommandString, sanitizeForDisplay } from '../../sanitizer.js';
import { parseDiagnostic } from '../../diagnostics/index.js';
import { captureSafeEnvironment } from '../../environment.js';
import { readGitMetadata } from '../../git.js';
import { tokenizeCommandLine } from '../../parser.js';
import { Platform, EventType, CaptureOrigin, FailureKind, Outcome, createCanonicalExecution } from '../model.js';

/**
 * Normalizes a Cursor agent failure hook payload (postToolUseFailure).
 *
 * @param {object} data - Parsed payload from Cursor
 * @param {object} [contextOptions={}] - Additional context
 * @returns {import('../model.js').CanonicalExecution}
 */
export function normalizeCursorPayload(data = {}, contextOptions = {}) {
  const sessionId = data.conversation_id || null;
  const toolName = data.tool_name || null;
  const input = data.tool_input || {};
  const rawCmd = (input.command || input.cmd || data.command || '').trim();
  const cwd = input.cwd || contextOptions.cwd || data.cwd || process.cwd();

  const output = data.tool_output || {};
  let exitCode = null;
  if (typeof output.exit_code === 'number') {
    exitCode = output.exit_code;
  } else if (typeof output.exitCode === 'number') {
    exitCode = output.exitCode;
  } else if (typeof data.exitCode === 'number') {
    exitCode = data.exitCode;
  }

  const rawStderr = output.stderr || data.error || '';
  const rawStdout = output.stdout || '';
  const stderr = sanitizeForDisplay(redactSecrets(rawStderr));
  const stdout = sanitizeForDisplay(redactSecrets(rawStdout));
  const durationMs = typeof data.duration_ms === 'number' && data.duration_ms >= 0 ? data.duration_ms : 0;

  const tokens = tokenizeCommandLine(rawCmd);
  const command = tokens[0] ? redactSecrets(tokens[0]) : redactSecrets(rawCmd);
  const args = redactCommandArgs(tokens.slice(1));
  const fullCommand = redactCommandString(rawCmd);

  const env = captureSafeEnvironment(process.env);
  const git = readGitMetadata(cwd);
  const diagnostic = parseDiagnostic(stderr, stdout, { command, cwd });

  let outcome = Outcome.UNKNOWN;
  if (exitCode === 0) outcome = Outcome.SUCCESS;
  else if (exitCode !== null && exitCode > 0) outcome = Outcome.FAILURE;
  else if (rawStderr || data.error) outcome = Outcome.FAILURE;

  let failureKind = FailureKind.EXECUTION_FAILURE;
  if (data.timedOut || output.timedOut) failureKind = FailureKind.TIMEOUT;

  return createCanonicalExecution({
    platform: Platform.CURSOR,
    eventType: EventType.POST_TOOL_USE_FAILURE,
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
    executionStarted: true,
    timedOut: failureKind === FailureKind.TIMEOUT,
    stdout,
    stderr,
    stdoutRaw: rawStdout,
    stderrRaw: rawStderr,
    diagnostic,
    environment: env,
    git
  });
}
