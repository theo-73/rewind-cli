import readline from 'node:readline';
import { formatJson } from '../formatter.js';
import { CliError } from '../errors.js';

/**
 * Handler for `rewind scrub [--yes] [--json]`.
 * Redacts raw secrets from journal.jsonl and isolated evidence files,
 * re-seals the cryptographic SHA-256 hash chain from sequence 1 to N,
 * updates the trusted checkpoint, and safely rebuilds all projections.
 *
 * @param {object} params
 * @param {import('../cli.js').CliContext} params.context
 * @returns {Promise<number>}
 */
export async function scrubCommand({ context }) {
  const { parsedArgs, storage, stdout, stdin, isTTY, styler } = context;
  const isJsonMode = Boolean(parsedArgs.flags.json);
  const hasYes = Boolean(parsedArgs.flags.yes || parsedArgs.flags.y || parsedArgs.flags.force);

  if (isTTY && !hasYes && !isJsonMode) {
    const s = styler;
    stdout.write(`\n${s.bold('REWIND JOURNAL SCRUB & RE-SEAL')}\n`);
    stdout.write(s.dim('────────────────────────────────────────────────────────────────────────\n'));
    stdout.write(`  This command will redact raw secrets across the historical journal,\n`);
    stdout.write(`  recompute cryptographic SHA-256 digests, and re-seal the tamper-evident hash chain.\n\n`);

    const rl = readline.createInterface({ input: stdin, output: stdout });
    const answer = await new Promise((resolve) => {
      rl.question('Proceed with scrubbing secrets and re-sealing journal? [y/N]: ', resolve);
    });
    rl.close();

    if (!answer || (answer.trim().toLowerCase() !== 'y' && answer.trim().toLowerCase() !== 'yes')) {
      stdout.write('\n' + s.dim('Scrub cancelled. No journal events were modified.') + '\n\n');
      return 0;
    }
  } else if (!isTTY && !hasYes && !isJsonMode) {
    throw new CliError('Confirmation required in non-interactive sessions. Re-run with --yes (-y).', {
      code: 'ERR_CONFIRMATION_REQUIRED',
      exitCode: 1
    });
  }

  const result = storage.scrubLedger();

  if (isJsonMode) {
    stdout.write(formatJson({
      status: 'success',
      scrubbedCount: result.scrubbedCount,
      totalEvents: result.totalEvents,
      headChainHash: result.headChainHash,
      hashChain: 'RE-SEALED'
    }) + '\n');
    return 0;
  }

  const s = styler;
  const termWidth = (stdout && typeof stdout.columns === 'number' && stdout.columns > 20)
    ? Math.min(stdout.columns, 80)
    : 72;
  const divider = s.dim('─'.repeat(termWidth));

  stdout.write(`\n${s.bold('JOURNAL SCRUB & RE-SEAL COMPLETE')}\n`);
  stdout.write(`${divider}\n`);
  stdout.write(`  ${s.dim('Total Events Evaluated:'.padEnd(26))} ${s.bold(String(result.totalEvents))}\n`);
  stdout.write(`  ${s.dim('Events Scrubbed:'.padEnd(26))} ${result.scrubbedCount > 0 ? s.green(String(result.scrubbedCount)) : s.dim('0 (clean)')}\n`);
  stdout.write(`  ${s.dim('Hash Chain Status:'.padEnd(26))} ${s.green('✔ RE-SEALED')}\n`);
  stdout.write(`  ${s.dim('Head Chain Hash:'.padEnd(26))} ${s.cyan(result.headChainHash.slice(0, 16) + '...')}\n`);
  stdout.write(`  ${s.dim('Projections:'.padEnd(26))} ${s.green('✔ REBUILT')}\n`);
  stdout.write(`${divider}\n`);
  stdout.write(`${s.dim('All sensitive arguments and outputs have been redacted and the ledger hash chain is cryptographically intact.')}\n\n`);

  return 0;
}
