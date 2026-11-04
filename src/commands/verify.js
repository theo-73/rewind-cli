import readline from 'node:readline';
import { MissingArgumentError, CliError, UsageError } from '../errors.js';
import { IncidentStatus } from '../storage/state.js';
import { executeAndCapture } from '../capture.js';
import { tokenizeCommandLine, hasShellOperators } from '../parser.js';
import { formatJson, formatBox } from '../formatter.js';
import { sanitizeForDisplay } from '../sanitizer.js';
import { normalizeId } from '../storage/store.js';
import { formatContradictionSection } from '../storage/contradiction.js';
import { captureSafeEnvironment } from '../environment.js';
import { readGitMetadata } from '../git.js';

/**
 * Handler for `rewind verify <id>`.
 * Loads the selected recovery record, displays and executes ONLY the explicitly stored
 * verification command, appends an immutable VerificationRun, updates trust loop state,
 * and runs contradiction analysis.
 *
 * @param {object} params
 * @param {import('../cli.js').CliContext} params.context
 * @returns {Promise<number>} - 0 if verified, non-zero if verification command failed
 */
export async function verifyCommand({ context }) {
  const { parsedArgs, config, storage, env, stdout, stderr, stdin, isTTY, styler } = context;
  const rawId = parsedArgs.positional[0];

  if (!rawId) {
    const { records } = storage.listRecords({ limit: 1, reverse: true });
    let msg = 'rewind verify <id>';
    if (records.length > 0) {
      msg = `rewind verify <id>\n\nTip: The latest incident is #${records[0].id}. Run "rewind verify ${records[0].id}".`;
    }
    throw new MissingArgumentError('id', msg);
  }

  const id = normalizeId(rawId);
  const record = storage.getRecord(id);
  if (!record) {
    throw new CliError(`Incident #${rawId} not found in ledger.`, {
      code: 'ERR_NOT_FOUND',
      exitCode: 1,
      details: { id: rawId, suggestion: 'Run "rewind history" to browse all past incidents.' }
    });
  }

  const isRecovered = record.status === IncidentStatus.RECOVERED || record.status === 'VERIFIED';
  if (isRecovered) {
    stdout.write(`\n  ${styler.green('✓')} Incident #${id} is already verified and sealed.\n\n`);
    return 0;
  }

  // Find the latest recovery attempt with a verifyCmd
  let targetAttempt = null;
  if (Array.isArray(record.recoveryAttempts)) {
    for (let i = record.recoveryAttempts.length - 1; i >= 0; i--) {
      if (record.recoveryAttempts[i].verifyCmd) {
        targetAttempt = record.recoveryAttempts[i];
        break;
      }
    }
  }

  const verifyCmd = targetAttempt?.verifyCmd;

  if (!verifyCmd) {
    throw new UsageError(
      `Incident #${id} has no explicit verification command recorded.\n` +
      `Run "rewind recover ${id} --verify-cmd \\"<command>\\"" before verifying.`
    );
  }

  const isJsonMode = Boolean(parsedArgs.flags.json);

  const hasYes = Boolean(parsedArgs.flags.yes || parsedArgs.flags.y || parsedArgs.flags.force);
  if (!hasYes) {
    if (!isTTY) {
      throw new CliError('Confirmation required to execute verification command in non-interactive sessions. Re-run with --yes (-y).', {
        code: 'ERR_CONFIRMATION_REQUIRED',
        exitCode: 1
      });
    }

    if (targetAttempt.source === 'mcp') {
      stdout.write(`\n  ${styler.yellow('⚠ WARNING: This verification command was suggested by an AI agent.')}\n`);
    }

    stdout.write(`\n  Verification Command:\n    ${styler.bold(styler.cyan('$ ' + sanitizeForDisplay(verifyCmd)))}\n\n`);
    const rl = readline.createInterface({ input: stdin, output: stdout });
    const answer = await new Promise((resolve) => {
      rl.question('  Run this command to verify? [y/N]: ', resolve);
    });
    rl.close();

    if (!answer || (answer.trim().toLowerCase() !== 'y' && answer.trim().toLowerCase() !== 'yes')) {
      stdout.write(`\n  ${styler.dim('Verification aborted by user.')}\n\n`);
      return 1;
    }
  }

  if (!isJsonMode) {
    const tag = styler.badge('rewind:verify', styler.cyan);
    stdout.write(`\n${tag} Executing user-approved verification command for Incident #${id} [Attempt #${targetAttempt.id}]:\n`);
    stdout.write(`  ${styler.bold(styler.cyan('$ ' + sanitizeForDisplay(verifyCmd)))}\n\n`);
  }

  // Execute ONLY the explicitly stored verification command
  const stdoutStream = isJsonMode ? null : stdout;
  const stderrStream = isJsonMode ? null : stderr;

  // Never infer shell execution — require explicit --shell flag
  const isShellCommand = Boolean(parsedArgs.flags.shell);
  const commandTokens = isShellCommand ? [verifyCmd] : tokenizeCommandLine(verifyCmd);

  const timeoutMs = typeof parsedArgs.flags.timeout === 'number' && parsedArgs.flags.timeout > 0
    ? parsedArgs.flags.timeout
    : 60000; // 60-second default safeguard against infinite loops

  const verifyResult = await executeAndCapture(commandTokens, {
    cwd: config.rootDir,
    env,
    stdoutStream,
    stderrStream,
    shell: isShellCommand,
    timeout: timeoutMs
  });

  const runOutput = (verifyResult.stdout || verifyResult.stderr || '').trim();
  const safeEnv = captureSafeEnvironment(env);
  const gitMeta = readGitMetadata(config.rootDir);

  // Atomically record immutable verification run
  const updated = storage.recordVerificationRun(id, targetAttempt.id, {
    command: verifyCmd,
    exitCode: typeof verifyResult.exitCode === 'number' ? verifyResult.exitCode : (verifyResult.success ? 0 : 1),
    durationMs: verifyResult.durationMs,
    output: runOutput,
    environment: safeEnv,
    git: gitMeta,
    environmentFingerprint: safeEnv.fingerprint
  });

  // Run contradiction check across ledger
  const conflictReport = storage.getContradictionReport(record.fingerprint);

  if (verifyResult.success) {
    const verifiedAtIso = new Date().toISOString();

    if (isJsonMode) {
      stdout.write(formatJson({
        status: 'success',
        verified: true,
        incidentStatus: updated.status,
        conflicts: conflictReport,
        data: updated
      }) + '\n');
      return 0;
    }

    const tag = styler.badge('rewind', styler.green);
    stdout.write(`\n${tag} ${styler.bold(styler.green('VERIFIED!'))} Incident #${id} [Attempt #${targetAttempt.id}] successfully validated under recorded conditions.\n`);

    const box = formatBox('✓ RECOVERY VERIFIED', [
      { label: 'Incident', value: `#${id}` },
      { label: 'Attempt', value: `#${targetAttempt.id}` },
      { label: 'Verify Command', value: verifyCmd },
      { label: 'Exit Code', value: '0 (Success)' },
      { label: 'Duration', value: `${verifyResult.durationMs}ms` },
      { label: 'Verified At', value: verifiedAtIso }
    ], styler, 'success');

    stdout.write(`\n${box}\n\n`);
    stdout.write(`The verified recovery has been sealed into the ledger.\n`);
    stdout.write(`Future occurrences of this failure fingerprint will detect this verified fix.\n`);

    if (conflictReport.hasConflicts) {
      stdout.write(`\n${formatContradictionSection(conflictReport, styler)}`);
    }

    stdout.write('\n');
    return 0;
  } else {
    const exitCode = typeof verifyResult.exitCode === 'number' ? verifyResult.exitCode : 1;
    const isTimeout = Boolean(verifyResult.timedOut);

    if (isJsonMode) {
      stdout.write(formatJson({
        status: 'failure',
        verified: false,
        timedOut: isTimeout,
        incidentStatus: updated.status,
        conflicts: conflictReport,
        data: updated
      }) + '\n');
      return exitCode;
    }

    const tag = styler.badge('rewind', styler.red);
    const failureMsg = isTimeout
      ? `Verification command timed out after ${timeoutMs}ms.`
      : `Verification command failed with exit code ${exitCode}.`;
    stderr.write(`\n${tag} ${styler.bold(styler.red('NOT VERIFIED:'))} ${failureMsg}\n`);

    const boxTitle = isTimeout
      ? '✗ VERIFICATION TIMED OUT (Preserved in Negative Memory)'
      : '✗ VERIFICATION FAILED (Preserved in Negative Memory)';

    const resultLabel = isTimeout ? `Timed out (${timeoutMs}ms limit)` : String(exitCode);

    const box = formatBox(boxTitle, [
      { label: 'Incident', value: `#${id}` },
      { label: 'Attempt', value: `#${targetAttempt.id} (Marked FAILED)` },
      { label: 'Verify Command', value: verifyCmd },
      { label: 'Result', value: resultLabel },
      { label: 'Duration', value: `${verifyResult.durationMs}ms` }
    ], styler, 'error');

    stderr.write(`\n${box}\n\n`);
    stderr.write(`Attempt #${targetAttempt.id} has been permanently sealed into negative memory as a failed approach.\n`);
    stderr.write(`Incident #${id} remains in state: ${styler.cyan('OPEN')}.\n`);
    stderr.write(`To try a new remediation, run: "${styler.cyan(`rewind recover ${id} --change "..." --verify-cmd "..."`)}"\n\n`);

    return exitCode;
  }
}

