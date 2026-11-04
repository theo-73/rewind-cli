import { InvalidArgumentError } from './errors.js';

/**
 * Result of parsing CLI arguments.
 * @typedef {object} ParsedArgs
 * @property {string|null} command - The subcommand to run (e.g. 'run', 'history', 'show', 'recover', 'verify', 'help')
 * @property {string[]} positional - Positional arguments for the subcommand
 * @property {object} flags - Parsed flags
 * @property {boolean} flags.help - Whether --help / -h was requested
 * @property {boolean} flags.version - Whether --version / -v was requested
 * @property {boolean} flags.json - Whether --json was requested
 * @property {boolean} flags.noColor - Whether --no-color was requested
 * @property {string|null} flags.root - Custom root directory path
 * @property {number|null} flags.limit - Limit for history listing
 * @property {string|null} flags.cause - Suspected cause text for recover command
 * @property {string|null} flags.change - Change made / remediation text for recover command
 * @property {string|null} flags.verifyCmd - Verification command string for recover command
 * @property {string[]} raw - The original raw argument array
 */

/**
 * Detects if a command line string contains unquoted shell control operators
 * (such as &&, ||, ;, |, &, >, <).
 *
 * @param {string} cmdString
 * @returns {boolean}
 */
export function hasShellOperators(cmdString) {
  if (!cmdString || typeof cmdString !== 'string') return false;
  let inDouble = false;
  let inSingle = false;

  for (let i = 0; i < cmdString.length; i++) {
    const char = cmdString[i];
    const nextChar = cmdString[i + 1];

    if (char === '\\' && (nextChar === '"' || nextChar === "'" || nextChar === '\\')) {
      i++;
      continue;
    }

    if (char === '"' && !inSingle) {
      inDouble = !inDouble;
      continue;
    }

    if (char === "'" && !inDouble) {
      inSingle = !inSingle;
      continue;
    }

    if (!inDouble && !inSingle) {
      if (char === ';' || char === '|' || char === '>' || char === '<') {
        return true;
      }
      if (char === '&') {
        return true;
      }
    }
  }

  return false;
}

/**
 * Tokenizes a command line string into an array of arguments,
 * respecting double quotes, single quotes, and Windows/Unix path separators.
 *
 * @param {string} cmdString
 * @returns {string[]}
 */
export function tokenizeCommandLine(cmdString) {
  if (!cmdString || typeof cmdString !== 'string') return [];
  const tokens = [];
  let current = '';
  let inDouble = false;
  let inSingle = false;

  for (let i = 0; i < cmdString.length; i++) {
    const char = cmdString[i];
    const nextChar = cmdString[i + 1];

    if (char === '\\' && (nextChar === '"' || nextChar === "'" || nextChar === '\\')) {
      current += nextChar;
      i++;
      continue;
    }

    if (char === '"' && !inSingle) {
      inDouble = !inDouble;
      continue;
    }

    if (char === "'" && !inDouble) {
      inSingle = !inSingle;
      continue;
    }

    if (/\s/.test(char) && !inDouble && !inSingle) {
      if (current.length > 0) {
        tokens.push(current);
        current = '';
      }
      continue;
    }

    current += char;
  }

  if (current.length > 0) {
    tokens.push(current);
  }

  return tokens;
}

/**
 * Parses raw argv arguments into structured command, positional args, and flags.
 *
 * @param {string[]} rawArgs - Array of argument strings (e.g. process.argv.slice(2))
 * @returns {ParsedArgs}
 */
export function parseArgs(rawArgs = []) {
  const flags = {
    help: false,
    version: false,
    json: false,
    noColor: false,
    root: null,
    limit: null,
    offset: null,
    cause: null,
    change: null,
    verifyCmd: null,
    fingerprint: null,
    explain: false,
    repair: false,
    dryRun: false,
    timeout: null,
    shell: false,
    fixed: false,
    cmd: null,
    exit: null,
    duration: null,
    cwd: null,
    stderr: null,
    output: null,
    includeUnverified: false,
    overwrite: false,
    force: false,
    yes: false,
    source: null,
    event: null
  };

  const positional = [];
  let command = null;
  const rawCommand = rawArgs.includes('hook') ? 'hook' : rawArgs.includes('completions') ? 'completions' : null;
  let i = 0;

  while (i < rawArgs.length) {
    const arg = rawArgs[i];

    // If we have already identified the command as 'run', check for run flags before the target command
    if (command === 'run') {
      if (positional.length === 0) {
        if (arg === '--help' || arg === '-h') {
          flags.help = true;
          i++;
          continue;
        }
        if (arg === '--shell' || arg === '-s') {
          flags.shell = true;
          i++;
          continue;
        }
        if (arg === '--json') {
          flags.json = true;
          i++;
          continue;
        }
        if (arg === '--no-color') {
          flags.noColor = true;
          i++;
          continue;
        }
        if (arg === '--root') {
          i++;
          if (i >= rawArgs.length || rawArgs[i].startsWith('-')) {
            throw new InvalidArgumentError('Option "--root" requires a path argument.');
          }
          flags.root = rawArgs[i];
          i++;
          continue;
        }
        if (arg.startsWith('--root=')) {
          const val = arg.slice('--root='.length);
          if (!val) {
            throw new InvalidArgumentError('Option "--root" requires a path argument.');
          }
          flags.root = val;
          i++;
          continue;
        }
        if (arg === '--') {
          i++;
          while (i < rawArgs.length) {
            positional.push(rawArgs[i]);
            i++;
          }
          break;
        }
      }
      positional.push(arg);
      i++;
      continue;
    }

    if (arg === '--help' || arg === '-h') {
      flags.help = true;
      i++;
    } else if (arg === '--version' || arg === '-v') {
      flags.version = true;
      i++;
    } else if (arg === '--json') {
      flags.json = true;
      i++;
    } else if (arg === '--no-color') {
      flags.noColor = true;
      i++;
    } else if (arg === '--shell' && (command === 'completions' || command === 'hook' || rawCommand === 'completions' || rawCommand === 'hook')) {
      i++;
      if (i >= rawArgs.length || rawArgs[i].startsWith('-')) {
        throw new InvalidArgumentError('Option "--shell" requires a shell name (bash, zsh, powershell, fish).');
      }
      flags.shell = rawArgs[i];
      i++;
    } else if (arg.startsWith('--shell=') && (command === 'completions' || command === 'hook' || rawCommand === 'completions' || rawCommand === 'hook')) {
      flags.shell = arg.slice('--shell='.length);
      i++;
    } else if (arg === '--shell') {
      flags.shell = true;
      i++;
    } else if (arg === '--timeout' || arg === '-t') {
      i++;
      if (i >= rawArgs.length || (rawArgs[i].startsWith('-') && !/^-\d+$/.test(rawArgs[i]))) {
        throw new InvalidArgumentError('Option "--timeout" requires an integer value (in milliseconds).');
      }
      const num = Number.parseInt(rawArgs[i], 10);
      if (Number.isNaN(num) || num < 1) {
        throw new InvalidArgumentError(`Option "--timeout" requires a positive integer (ms), got "${rawArgs[i]}".`);
      }
      flags.timeout = num;
      i++;
    } else if (arg.startsWith('--timeout=')) {
      const val = arg.slice('--timeout='.length);
      const num = Number.parseInt(val, 10);
      if (!val || Number.isNaN(num) || num < 1) {
        throw new InvalidArgumentError(`Option "--timeout" requires a positive integer (ms), got "${val}".`);
      }
      flags.timeout = num;
      i++;
    } else if (arg === '--root') {
      i++;
      if (i >= rawArgs.length || rawArgs[i].startsWith('-')) {
        throw new InvalidArgumentError('Option "--root" requires a path argument.');
      }
      flags.root = rawArgs[i];
      i++;
    } else if (arg.startsWith('--root=')) {
      const val = arg.slice('--root='.length);
      if (!val) {
        throw new InvalidArgumentError('Option "--root" requires a path argument.');
      }
      flags.root = val;
      i++;
    } else if (arg === '--limit' || arg === '-n') {
      i++;
      if (i >= rawArgs.length || (rawArgs[i].startsWith('-') && !/^-\d+$/.test(rawArgs[i]))) {
        throw new InvalidArgumentError('Option "--limit" requires an integer value.');
      }
      const num = Number.parseInt(rawArgs[i], 10);
      if (Number.isNaN(num) || num < 1) {
        throw new InvalidArgumentError(`Option "--limit" requires a positive integer, got "${rawArgs[i]}".`);
      }
      flags.limit = num;
      i++;
    } else if (arg.startsWith('--limit=')) {
      const val = arg.slice('--limit='.length);
      const num = Number.parseInt(val, 10);
      if (!val || Number.isNaN(num) || num < 1) {
        throw new InvalidArgumentError(`Option "--limit" requires a positive integer, got "${val}".`);
      }
      flags.limit = num;
      i++;
    } else if (arg === '--offset') {
      i++;
      if (i >= rawArgs.length || (rawArgs[i].startsWith('-') && !/^-\d+$/.test(rawArgs[i]))) {
        throw new InvalidArgumentError('Option "--offset" requires a non-negative integer value.');
      }
      const num = Number.parseInt(rawArgs[i], 10);
      if (Number.isNaN(num) || num < 0) {
        throw new InvalidArgumentError(`Option "--offset" requires a non-negative integer, got "${rawArgs[i]}".`);
      }
      flags.offset = num;
      i++;
    } else if (arg.startsWith('--offset=')) {
      const val = arg.slice('--offset='.length);
      const num = Number.parseInt(val, 10);
      if (!val || Number.isNaN(num) || num < 0) {
        throw new InvalidArgumentError(`Option "--offset" requires a non-negative integer, got "${val}".`);
      }
      flags.offset = num;
      i++;
    } else if (arg === '--cause' || arg === '-c') {
      i++;
      if (i >= rawArgs.length || rawArgs[i].startsWith('-')) {
        throw new InvalidArgumentError('Option "--cause" requires a text value.');
      }
      flags.cause = rawArgs[i];
      i++;
    } else if (arg.startsWith('--cause=')) {
      flags.cause = arg.slice('--cause='.length);
      i++;
    } else if (arg === '--change' || arg === '--fix' || arg === '-m') {
      i++;
      if (i >= rawArgs.length || rawArgs[i].startsWith('-')) {
        throw new InvalidArgumentError('Option "--change" requires a text value.');
      }
      flags.change = rawArgs[i];
      i++;
    } else if (arg.startsWith('--change=')) {
      flags.change = arg.slice('--change='.length);
      i++;
    } else if (arg === '--verify-cmd' || arg === '--verify') {
      i++;
      if (i >= rawArgs.length || rawArgs[i].startsWith('-')) {
        throw new InvalidArgumentError('Option "--verify-cmd" requires a command string.');
      }
      flags.verifyCmd = rawArgs[i];
      i++;
    } else if (arg.startsWith('--verify-cmd=')) {
      flags.verifyCmd = arg.slice('--verify-cmd='.length);
      i++;
    } else if (arg === '--fingerprint' || arg === '-f') {
      i++;
      if (i >= rawArgs.length || rawArgs[i].startsWith('-')) {
        throw new InvalidArgumentError('Option "--fingerprint" requires a fingerprint hash string.');
      }
      flags.fingerprint = rawArgs[i];
      i++;
    } else if (arg.startsWith('--fingerprint=')) {
      flags.fingerprint = arg.slice('--fingerprint='.length);
      i++;
    } else if (arg === '--explain') {
      flags.explain = true;
      i++;
    } else if (arg === '--repair') {
      flags.repair = true;
      i++;
    } else if (arg === '--dry-run') {
      flags.dryRun = true;
      i++;
    } else if (arg === '--fixed') {
      flags.fixed = true;
      i++;
    } else if (arg === '--baseline') {
      flags.baseline = true;
      i++;
    } else if (arg === '--baseline-failed') {
      flags.baselineFailed = true;
      i++;
    } else if (arg === '--cmd') {
      i++;
      if (i >= rawArgs.length || rawArgs[i].startsWith('-')) {
        throw new InvalidArgumentError('Option "--cmd" requires a command string.');
      }
      flags.cmd = rawArgs[i];
      i++;
    } else if (arg.startsWith('--cmd=')) {
      flags.cmd = arg.slice('--cmd='.length);
      i++;
    } else if (arg === '--exit') {
      i++;
      if (i >= rawArgs.length || (rawArgs[i].startsWith('-') && !/^-\d+$/.test(rawArgs[i]))) {
        throw new InvalidArgumentError('Option "--exit" requires an integer exit code.');
      }
      const num = Number.parseInt(rawArgs[i], 10);
      if (Number.isNaN(num)) {
        throw new InvalidArgumentError(`Option "--exit" requires an integer, got "${rawArgs[i]}".`);
      }
      flags.exit = num;
      i++;
    } else if (arg.startsWith('--exit=')) {
      const val = arg.slice('--exit='.length);
      const num = Number.parseInt(val, 10);
      if (!val || Number.isNaN(num)) {
        throw new InvalidArgumentError(`Option "--exit" requires an integer, got "${val}".`);
      }
      flags.exit = num;
      i++;
    } else if (arg === '--duration') {
      i++;
      if (i >= rawArgs.length || (rawArgs[i].startsWith('-') && !/^-\d+$/.test(rawArgs[i]))) {
        throw new InvalidArgumentError('Option "--duration" requires an integer (in ms).');
      }
      const num = Number.parseInt(rawArgs[i], 10);
      if (Number.isNaN(num) || num < 0) {
        throw new InvalidArgumentError(`Option "--duration" requires a non-negative integer (ms), got "${rawArgs[i]}".`);
      }
      flags.duration = num;
      i++;
    } else if (arg.startsWith('--duration=')) {
      const val = arg.slice('--duration='.length);
      const num = Number.parseInt(val, 10);
      if (!val || Number.isNaN(num) || num < 0) {
        throw new InvalidArgumentError(`Option "--duration" requires a non-negative integer (ms), got "${val}".`);
      }
      flags.duration = num;
      i++;
    } else if (arg === '--cwd') {
      i++;
      if (i >= rawArgs.length || rawArgs[i].startsWith('-')) {
        throw new InvalidArgumentError('Option "--cwd" requires a directory path.');
      }
      flags.cwd = rawArgs[i];
      i++;
    } else if (arg.startsWith('--cwd=')) {
      flags.cwd = arg.slice('--cwd='.length);
      i++;
    } else if (arg === '--stderr') {
      i++;
      if (i >= rawArgs.length) {
        flags.stderr = '';
      } else {
        flags.stderr = rawArgs[i];
        i++;
      }
    } else if (arg.startsWith('--stderr=')) {
      flags.stderr = arg.slice('--stderr='.length);
      i++;
    } else if (arg === '--output' || arg === '-o') {
      i++;
      if (i >= rawArgs.length || rawArgs[i].startsWith('-')) {
        throw new InvalidArgumentError('Option "--output" requires a file path argument.');
      }
      flags.output = rawArgs[i];
      i++;
    } else if (arg.startsWith('--output=')) {
      const val = arg.slice('--output='.length);
      if (!val) {
        throw new InvalidArgumentError('Option "--output" requires a file path argument.');
      }
      flags.output = val;
      i++;
    } else if (arg === '--include-unverified' || arg === '--all') {
      flags.includeUnverified = true;
      i++;
    } else if (arg === '--overwrite') {
      flags.overwrite = true;
      i++;
    } else if (arg === '--force' || arg === '--yes' || arg === '-y') {
      flags.force = true;
      flags.yes = true;
      i++;
    } else if (arg === '--quiet' || arg === '-q') {
      flags.quiet = true;
      i++;
    } else if (arg === '--data') {
      i++;
      if (i >= rawArgs.length) {
        throw new InvalidArgumentError('Option "--data" requires a JSON string value.');
      }
      flags.data = rawArgs[i];
      i++;
    } else if (arg.startsWith('--data=')) {
      flags.data = arg.slice('--data='.length);
      i++;
    } else if (arg === '--file') {
      i++;
      if (i >= rawArgs.length || rawArgs[i].startsWith('-')) {
        throw new InvalidArgumentError('Option "--file" requires a file path argument.');
      }
      flags.file = rawArgs[i];
      i++;
    } else if (arg.startsWith('--file=')) {
      flags.file = arg.slice('--file='.length);
      i++;
    } else if (arg === '--source' || arg === '-s') {
      i++;
      if (i >= rawArgs.length || rawArgs[i].startsWith('-')) {
        throw new InvalidArgumentError('Option "--source" requires a platform value (cursor, gemini, codex, claude, generic).');
      }
      flags.source = rawArgs[i];
      i++;
    } else if (arg.startsWith('--source=')) {
      const val = arg.slice('--source='.length);
      if (!val) {
        throw new InvalidArgumentError('Option "--source" requires a platform value (cursor, gemini, codex, claude, generic).');
      }
      flags.source = val;
      i++;
    } else if (arg === '--event') {
      i++;
      if (i >= rawArgs.length || rawArgs[i].startsWith('-')) {
        throw new InvalidArgumentError('Option "--event" requires an event type value.');
      }
      flags.event = rawArgs[i];
      i++;
    } else if (arg.startsWith('--event=')) {
      const val = arg.slice('--event='.length);
      if (!val) {
        throw new InvalidArgumentError('Option "--event" requires an event type value.');
      }
      flags.event = val;
      i++;
    } else if (arg === '--agent' || arg === '-a') {
      i++;
      if (i >= rawArgs.length || rawArgs[i].startsWith('-')) {
        throw new InvalidArgumentError('Option "--agent" requires an agent name (cursor, gemini, codex, claude).');
      }
      flags.agent = rawArgs[i];
      i++;
    } else if (arg.startsWith('--agent=')) {
      const val = arg.slice('--agent='.length);
      if (!val) {
        throw new InvalidArgumentError('Option "--agent" requires an agent name (cursor, gemini, codex, claude).');
      }
      flags.agent = val;
      i++;
    } else if (arg === '--profile') {
      i++;
      if (i >= rawArgs.length || rawArgs[i].startsWith('-')) {
        throw new InvalidArgumentError('Option "--profile" requires a profile name (core, full).');
      }
      flags.profile = rawArgs[i];
      i++;
    } else if (arg.startsWith('--profile=')) {
      flags.profile = arg.slice('--profile='.length);
      i++;
    } else if (arg.startsWith('-')) {
      throw new InvalidArgumentError(`Unknown option: "${arg}". Run "rewind --help" for usage.`);
    } else {
      if (command === null) {
        command = arg;
      } else {
        positional.push(arg);
      }
      i++;
    }
  }

  // Support "rewind help [subcommand]" by normalizing to help command and target subcommand
  if (command === 'help') {
    flags.help = true;
    if (positional.length > 0) {
      command = positional[0];
      positional.shift();
    } else {
      command = null;
    }
  }

  return {
    command,
    positional,
    flags,
    raw: [...rawArgs]
  };
}
