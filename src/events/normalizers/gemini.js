import { redactSecrets, redactCommandArgs, redactCommandString, sanitizeForDisplay } from '../../sanitizer.js';
import { parseDiagnostic } from '../../diagnostics/index.js';
import { captureSafeEnvironment } from '../../environment.js';
import { readGitMetadata } from '../../git.js';
import { tokenizeCommandLine } from '../../parser.js';
import { Platform, EventType, CaptureOrigin, FailureKind, Outcome, createCanonicalExecution } from '../model.js';

/**
 * Normalizes a Gemini CLI agent failure hook payload (AfterTool).
 *
 * @param {object} data - Parsed payload from Gemini CLI
 * @param {object} [contextOptions={}] - Additional context
 * @returns {import('../model.js').CanonicalExecution}
 */
export function normalizeGeminiPayload(data = {}, contextOptions = {}) {
  const sessionId = data.session_id || null;
  const toolName = data.tool_name || null;
  const params = data.parameters || data.tool_input || {};
  const rawCmd = (params.command || params.cmd || data.command || '').trim();
  const cwd = params.cwd || contextOptions.cwd || data.cwd || process.cwd();

  const res = data.result || data.tool_response || {};
  let exitCode = null;
  if (typeof res.exit_code === 'number') {
    exitCode = res.exit_code;
  } else if (typeof res.exitCode === 'number') {
    exitCode = res.exitCode;
  } else if (typeof data.exitCode === 'number') {
    exitCode = data.exitCode;
  }

  const rawStderr = res.error || res.stderr || data.error || '';
  const rawStdout = res.stdout || '';
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
  if (data.timedOut || res.timedOut) failureKind = FailureKind.TIMEOUT;

  return createCanonicalExecution({
    platform: Platform.GEMINI,
    eventType: EventType.AFTER_TOOL,
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
