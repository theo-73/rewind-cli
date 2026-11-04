import { MissingArgumentError } from '../errors.js';
import { executeAndCapture } from '../capture.js';
import { hasShellOperators } from '../parser.js';
import { formatJson } from '../formatter.js';
import { IncidentStatus, ProofTier, computeProofTier } from '../storage/state.js';
import { sanitizeForDisplay } from '../sanitizer.js';
import { CaptureService } from '../storage/service.js';
import { Platform, EventType, CaptureOrigin } from '../events/model.js';

/**
 * Handler for `rewind run <command...>`.
 * Executes the user-requested process, streams output live, captures all diagnostic
 * lifecycle evidence, persists failure records into local storage, detects regressions,
 * surfaces verified fixes, known failed approaches, and staleness warnings,
 * and strictly propagates the child process's exit code.
 *
 * @param {object} params
 * @param {import('../cli.js').CliContext} params.context
 * @returns {Promise<number>} - Child process exit code
 */
export async function runCommand({ context }) {
  const { parsedArgs, config, storage, env, stdout, stderr, styler } = context;
  const targetCommand = parsedArgs.positional;

  if (!targetCommand || targetCommand.length === 0) {
    throw new MissingArgumentError('command', 'rewind run <command...>');
  }

  const isJsonMode = Boolean(parsedArgs.flags.json);

  // If in JSON mode, avoid multiplexing live stream to stdout to preserve pure JSON output
  const stdoutStream = isJsonMode ? null : stdout;
  const stderrStream = isJsonMode ? null : stderr;

  const isShellCommand = Boolean(parsedArgs.flags.shell) ||
    (targetCommand.length === 1 && hasShellOperators(targetCommand[0])) ||
    targetCommand.some(token => ['&&', '||', ';', '|', '&', '>', '<'].includes(token));

  const result = await executeAndCapture(targetCommand, {
    cwd: config.rootDir,
    env,
    stdoutStream,
    stderrStream,
    shell: isShellCommand
  });

  let savedRecord = null;
  // Automatically ingest failure records via unified CaptureService
  if (!result.success && storage) {
    try {
      const canonical = {
        ...result,
        platform: Platform.CLI,
        eventType: EventType.COMMAND,
        captureOrigin: CaptureOrigin.REWIND_RUN
      };

      const ingestion = CaptureService.ingestExecution(canonical, storage, {
        captureOrigin: CaptureOrigin.REWIND_RUN
      });

      savedRecord = ingestion.record;

      if (ingestion.classification === 'PROMOTE' && savedRecord && !isJsonMode && stderr && typeof stderr.write === 'function') {
        const s = styler;
        const idText = s.bold(`#${savedRecord.id}`);

        const decision = ingestion.decision;
        let isRegression = savedRecord.status === IncidentStatus.REGRESSED && savedRecord.regressionOf;
        if (isRegression) {
          const priorRecord = storage.getRecord(savedRecord.regressionOf);
          const priorIsProven = priorRecord && Array.isArray(priorRecord.recoveryAttempts) && priorRecord.recoveryAttempts.some(
            (a) => computeProofTier(a) === ProofTier.PROVEN
          );
          if (!priorIsProven) {
            isRegression = false;
          }
        }
        const regBadge = isRegression ? ` ${s.red('(REGRESSION)')}` : '';

        if (decision.action === 'SURFACE') {
          const fix = decision.bestCandidate;
          const tag = s.badge('rewind', s.green);
          const originInc = fix.incidentId ? s.bold(`#${fix.incidentId}`) : '';
          const fixChange = sanitizeForDisplay(fix.change || '');
          stderr.write(`\n${tag} Known failure${regBadge} · verified recovery: "${s.bold(fixChange)}" · ${originInc}\n`);
          if (fix.verifyCmd) {
            stderr.write(`  Verify with: ${s.cyan(sanitizeForDisplay(fix.verifyCmd))}\n`);
          }
        } else if (decision.action === 'CAUTION') {
          const tag = s.badge('rewind', s.yellow);
          stderr.write(`\n${tag} Possible match${regBadge} (${s.dim(decision.reason)}) · Run "${s.cyan(`rewind show ${savedRecord.id}`)}"\n`);
        } else {
          const tag = s.badge('rewind', s.yellow);
          stderr.write(`\n${tag} Recorded failure as incident ${idText}${regBadge}. Run "${s.cyan(`rewind show ${savedRecord.id}`)}" to inspect.\n`);
        }

        // Relevant failed approaches (up to 2, quiet single-line warnings)
        if (decision.relevantFailedApproaches && decision.relevantFailedApproaches.length > 0) {
          for (const fa of decision.relevantFailedApproaches.slice(0, 2)) {
            const cleanChange = sanitizeForDisplay(fa.change || '');
            stderr.write(`  ${s.red('✗')} Previously failed: "${cleanChange}"\n`);
          }
        }
        stderr.write('\n');
      }
    } catch (storageErr) {
      if (!isJsonMode && stderr && typeof stderr.write === 'function') {
        stderr.write(`\n[rewind:warning] Failed to persist incident record: ${storageErr.message}\n\n`);
      }
    }
  }

  if (isJsonMode) {
    stdout.write(formatJson({
      status: result.success ? 'success' : 'failure',
      incidentId: savedRecord ? savedRecord.id : null,
      data: savedRecord || result
    }) + '\n');
  }

  // Propagate exact child exit code
  return typeof result.exitCode === 'number' ? result.exitCode : (result.success ? 0 : 1);
}

