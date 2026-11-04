import { UnknownCommandError } from './errors.js';
import { helpCommand } from './commands/help.js';
import { versionCommand } from './commands/version.js';
import { runCommand } from './commands/run.js';
import { historyCommand } from './commands/history.js';
import { showCommand } from './commands/show.js';
import { recoverCommand } from './commands/recover.js';
import { verifyCommand } from './commands/verify.js';
import { searchCommand } from './commands/search.js';
import { verifyIntegrityCommand } from './commands/verify_integrity.js';
import { rebuildCommand } from './commands/rebuild.js';
import { patternsCommand } from './commands/patterns.js';
import { contextCommand } from './commands/context.js';
import { doctorCommand } from './commands/doctor.js';
import { triageCommand } from './commands/triage.js';
import { hookCommand } from './commands/hook.js';
import { exportSharedCommand } from './commands/export_shared.js';
import { importSharedCommand } from './commands/import_shared.js';
import { initCommand } from './commands/init.js';
import { statsCommand } from './commands/stats.js';
import { clearCommand } from './commands/clear.js';
import { completionsCommand } from './commands/completions.js';
import { mcpCommand } from './commands/mcp.js';
import { eventCommand } from './commands/event.js';
import { setupCommand } from './commands/setup.js';
import { scrubCommand } from './commands/scrub.js';

export const COMMANDS = Object.freeze({
  run: runCommand,
  history: historyCommand,
  show: showCommand,
  recover: recoverCommand,
  triage: triageCommand,
  hook: hookCommand,
  'export-shared': exportSharedCommand,
  export_shared: exportSharedCommand,
  export: exportSharedCommand,
  'import-shared': importSharedCommand,
  import_shared: importSharedCommand,
  import: importSharedCommand,
  verify: verifyCommand,
  search: searchCommand,
  patterns: patternsCommand,
  context: contextCommand,
  doctor: doctorCommand,
  'verify-integrity': verifyIntegrityCommand,
  verify_integrity: verifyIntegrityCommand,
  rebuild: rebuildCommand,
  init: initCommand,
  stats: statsCommand,
  clear: clearCommand,
  completions: completionsCommand,
  mcp: mcpCommand,
  event: eventCommand,
  setup: setupCommand,
  scrub: scrubCommand,
  help: helpCommand,
  version: versionCommand
});

/**
 * Dispatches parsed arguments to the appropriate command handler.
 *
 * @param {object} params
 * @param {import('./cli.js').CliContext} params.context
 * @returns {Promise<number>}
 */
export async function dispatch({ context }) {
  const { parsedArgs } = context;

  // Handle global --version / -v flag
  if (parsedArgs.flags.version) {
    return await versionCommand({ context });
  }

  // Handle global --help / -h flag or explicit 'help' command
  if (parsedArgs.flags.help) {
    return await helpCommand({ commandName: parsedArgs.command, context });
  }

  // If no command provided, display top-level help
  if (!parsedArgs.command) {
    return await helpCommand({ commandName: null, context });
  }

  const handler = COMMANDS[parsedArgs.command];
  if (!handler) {
    throw new UnknownCommandError(parsedArgs.command);
  }

  return await handler({ context });
}
