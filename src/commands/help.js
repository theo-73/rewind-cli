/**
 * Help command documentation and formatting.
 */

const COMMAND_DOCS = {
  run: {
    usage: 'rewind run <command...>',
    description: 'Execute a command, capture failure evidence on non-zero exit, and track recovery context.',
    arguments: [
      { name: '<command...>', description: 'Command and arguments to execute' }
    ],
    options: [
      { flag: '--no-color', description: 'Disable ANSI color formatting' },
      { flag: '--root <path>', description: 'Explicit project root / ledger directory' }
    ],
    examples: [
      'rewind run npm test',
      'rewind run cargo build --release',
      'rewind run pytest tests/test_core.py'
    ]
  },
  history: {
    usage: 'rewind history [options]',
    description: 'List failure records and recovery timeline from the local ledger.',
    arguments: [],
    options: [
      { flag: '--limit <N>, -n <N>', description: 'Limit number of entries displayed' },
      { flag: '--json', description: 'Output history in JSON format' },
      { flag: '--no-color', description: 'Disable ANSI color formatting' },
      { flag: '--root <path>', description: 'Explicit project root / ledger directory' }
    ],
    examples: [
      'rewind history',
      'rewind history --limit 5',
      'rewind history --json'
    ]
  },
  show: {
    usage: 'rewind show <id> [options]',
    description: 'Inspect full failure details, preserved environment, recovery attempts, and verification status for a specific incident ID.',
    arguments: [
      { name: '<id>', description: 'Incident ID to inspect' }
    ],
    options: [
      { flag: '--json', description: 'Output incident details in JSON format' },
      { flag: '--no-color', description: 'Disable ANSI color formatting' },
      { flag: '--root <path>', description: 'Explicit project root / ledger directory' }
    ],
    examples: [
      'rewind show 1',
      'rewind show 1 --json'
    ]
  },
  recover: {
    usage: 'rewind recover <id> [options]',
    description: 'Guide recovery for a failed incident and record attempted remediation steps.',
    arguments: [
      { name: '<id>', description: 'Incident ID to recover' }
    ],
    options: [
      { flag: '--cause <text>', description: 'Suspected root cause (Provenance: USER_REPORTED)' },
      { flag: '--change <text>', description: 'Remediation action taken (Provenance: USER_REPORTED)' },
      { flag: '--verify-cmd <cmd>', description: 'Explicit verification command' },
      { flag: '--fixed', description: 'Mark remediation as applied by user (Status: FIXED, Quality: UNVERIFIED)' },
      { flag: '--no-color', description: 'Disable ANSI color formatting' },
      { flag: '--root <path>', description: 'Explicit project root / ledger directory' }
    ],
    examples: [
      'rewind recover 1 --cause "Bad config" --change "Updated port" --verify-cmd "npm test"',
      'rewind recover 1 --change "Patched connection pool size" --fixed --verify-cmd "npm test"'
    ]
  },
  triage: {
    usage: 'rewind triage [id] [options]',
    description: 'Interactive 7-step guided recovery triage workflow to record causes, fixes, and run verification.',
    arguments: [
      { name: '[id]', description: 'Optional incident ID to triage (prompts for selection if omitted)' }
    ],
    options: [
      { flag: '--timeout <ms>, -t <ms>', description: 'Maximum verification execution time before timeout (default: 60000ms)' },
      { flag: '--shell', description: 'Force verification execution inside system shell' },
      { flag: '--no-color', description: 'Disable ANSI color formatting' },
      { flag: '--root <path>', description: 'Explicit project root / ledger directory' }
    ],
    examples: [
      'rewind triage',
      'rewind triage 1',
      'rewind triage 1 --timeout 30000'
    ]
  },
  hook: {
    usage: 'rewind hook <shell|record> [options]',
    description: 'Print shell integration scripts for bash, zsh, or powershell, or record failed commands passively.',
    arguments: [
      { name: '<shell>', description: 'Shell type: "bash", "zsh", or "powershell" (prints hook script)' }
    ],
    options: [
      { flag: '--no-color', description: 'Disable ANSI color formatting' },
      { flag: '--root <path>', description: 'Explicit project root / ledger directory' }
    ],
    examples: [
      'eval "$(rewind hook bash)"',
      'eval "$(rewind hook zsh)"',
      'Invoke-Expression (& rewind hook powershell | Out-String)',
      'rewind hook bash',
      'rewind hook powershell'
    ]
  },
  'export-shared': {
    usage: 'rewind export-shared [options]',
    description: 'Export verified recovery knowledge into a sanitized, portable shared recovery bundle for team collaboration.',
    arguments: [],
    options: [
      { flag: '--output <path>, -o <path>', description: 'Destination bundle file path (default: shared-recovery.json)' },
      { flag: '--include-unverified', description: 'Include unverified recovery proposals and open incidents' },
      { flag: '--json', description: 'Output export summary as machine-readable JSON' },
      { flag: '--no-color', description: 'Disable ANSI color formatting' },
      { flag: '--root <path>', description: 'Explicit project root / ledger directory' }
    ],
    examples: [
      'rewind export-shared',
      'rewind export-shared -o shared-recovery.json',
      'rewind export-shared --include-unverified'
    ]
  },
  'import-shared': {
    usage: 'rewind import-shared [file] [options]',
    description: 'Import recovery knowledge from a shared recovery bundle into local ledger as external evidence.',
    arguments: [
      { name: '[file]', description: 'Path to shared recovery bundle file (default: shared-recovery.json)' }
    ],
    options: [
      { flag: '--dry-run', description: 'Preview bundle contents without modifying the local ledger' },
      { flag: '--overwrite', description: 'Force overwrite existing duplicate records' },
      { flag: '--json', description: 'Output import summary as machine-readable JSON' },
      { flag: '--no-color', description: 'Disable ANSI color formatting' },
      { flag: '--root <path>', description: 'Explicit project root / ledger directory' }
    ],
    examples: [
      'rewind import-shared shared-recovery.json',
      'rewind import-shared --dry-run',
      'rewind import-shared shared-recovery.json --json'
    ]
  },
  verify: {
    usage: 'rewind verify <id> [options]',
    description: 'Execute the verification command for an incident to validate the fix and seal the verified-recovery record.',
    arguments: [
      { name: '<id>', description: 'Incident ID to verify' }
    ],
    options: [
      { flag: '--timeout <ms>, -t <ms>', description: 'Maximum execution time before timeout (default: 60000ms)' },
      { flag: '--shell', description: 'Force execution inside system shell' },
      { flag: '--json', description: 'Output verification results as JSON' },
      { flag: '--no-color', description: 'Disable ANSI color formatting' },
      { flag: '--root <path>', description: 'Explicit project root / ledger directory' }
    ],
    examples: [
      'rewind verify 1',
      'rewind verify 1 --timeout 30000',
      'rewind verify 1 --json'
    ]
  },
  search: {
    usage: 'rewind search <query...> [options]',
    description: 'Search historical failures by error message, keywords, or fingerprint using conservative similarity scoring.',
    arguments: [
      { name: '<query...>', description: 'Search terms or error message snippet' }
    ],
    options: [
      { flag: '--limit <N>, -n <N>', description: 'Limit number of candidate matches' },
      { flag: '--json', description: 'Output search results as JSON' },
      { flag: '--no-color', description: 'Disable ANSI color formatting' },
      { flag: '--root <path>', description: 'Explicit project root / ledger directory' }
    ],
    examples: [
      'rewind search "database connection pool"',
      'rewind search "ECONNREFUSED"',
      'rewind search 83282360259b'
    ]
  },
  patterns: {
    usage: 'rewind patterns [options]',
    description: 'Analyze historical failure and recovery patterns into deterministic, evidence-backed diagnostics.',
    arguments: [],
    options: [
      { flag: '--fingerprint <hash>, -f <hash>', description: 'Filter pattern diagnostics to a specific fingerprint family' },
      { flag: '--explain', description: 'Display underlying rules, criteria, and evidence reasoning for each classification' },
      { flag: '--limit <N>, -n <N>', description: 'Limit number of pattern families displayed' },
      { flag: '--json', description: 'Output pattern report in machine-readable JSON' },
      { flag: '--no-color', description: 'Disable ANSI color formatting' },
      { flag: '--root <path>', description: 'Explicit project root / ledger directory' }
    ],
    examples: [
      'rewind patterns',
      'rewind patterns --fingerprint A91BF2',
      'rewind patterns --explain',
      'rewind patterns --json'
    ]
  },
  context: {
    usage: 'rewind context [latest|<id>] [options]',
    description: 'Output structured diagnostic failure context, verified remedies, negative memory, and non-causal deltas for coding agents.',
    arguments: [
      { name: '[latest|<id>]', description: 'Target incident ID or "latest" (defaults to latest failure)' }
    ],
    options: [
      { flag: '--json', description: 'Output pure structured JSON for machine/agent consumption' },
      { flag: '--no-color', description: 'Disable ANSI color formatting' },
      { flag: '--root <path>', description: 'Explicit project root / ledger directory' }
    ],
    examples: [
      'rewind context latest --json',
      'rewind context 1 --json',
      'rewind context'
    ]
  },
  'verify-integrity': {
    usage: 'rewind verify-integrity [options]',
    description: 'Perform a strictly read-only 4-layer cryptographic audit across the journal, hash chain, checkpoint, and derived views.',
    arguments: [],
    options: [
      { flag: '--json', description: 'Output audit report as JSON' },
      { flag: '--no-color', description: 'Disable ANSI color formatting' },
      { flag: '--root <path>', description: 'Explicit project root / ledger directory' }
    ],
    examples: [
      'rewind verify-integrity',
      'rewind verify-integrity --json'
    ]
  },
  rebuild: {
    usage: 'rewind rebuild [options]',
    description: 'Reconstruct all derived incident projection records in .rewind/records/ from the authoritative journal.',
    arguments: [],
    options: [
      { flag: '--json', description: 'Output rebuild summary as JSON' },
      { flag: '--no-color', description: 'Disable ANSI color formatting' },
      { flag: '--root <path>', description: 'Explicit project root / ledger directory' }
    ],
    examples: [
      'rewind rebuild',
      'rewind rebuild --json'
    ]
  },
  init: {
    usage: 'rewind init [options]',
    description: 'Initialize a new local ledger and shell hooks in the current project.',
    arguments: [],
    options: [
      { flag: '--no-color', description: 'Disable ANSI color formatting' }
    ],
    examples: ['rewind init']
  },
  stats: {
    usage: 'rewind stats [options]',
    description: 'View statistics and patterns across all recorded incidents.',
    arguments: [],
    options: [
      { flag: '--json', description: 'Output as JSON' },
      { flag: '--no-color', description: 'Disable ANSI color formatting' }
    ],
    examples: ['rewind stats', 'rewind stats --json']
  },
  clear: {
    usage: 'rewind clear [options]',
    description: 'Permanently delete the local ledger and all incident records.',
    arguments: [],
    options: [
      { flag: '--force, -y', description: 'Skip confirmation prompt' }
    ],
    examples: ['rewind clear', 'rewind clear --force']
  },
  completions: {
    usage: 'rewind completions <shell>',
    description: 'Generate tab completion scripts for your shell (bash, zsh, powershell, fish).',
    arguments: [
      { name: '<shell>', description: 'Target shell' }
    ],
    options: [],
    examples: ['rewind completions bash']
  },
  mcp: {
    usage: 'rewind mcp',
    description: 'Start MCP server on stdio for integration with AI coding agents.',
    arguments: [],
    options: [],
    examples: ['rewind mcp']
  },
  doctor: {
    usage: 'rewind doctor [options]',
    description: 'Run comprehensive self-diagnostics on ledger integrity, storage consistency, configuration, and runtime health.',
    arguments: [],
    options: [
      { flag: '--repair', description: 'Safely clean orphan temporary files and rebuild derived projections' },
      { flag: '--dry-run', description: 'Preview planned repairs without modifying disk' },
      { flag: '--json', description: 'Output diagnostic report in machine-readable JSON' },
      { flag: '--no-color', description: 'Disable ANSI color formatting' },
      { flag: '--root <path>', description: 'Explicit project root / ledger directory' }
    ],
    examples: [
      'rewind doctor',
      'rewind doctor --repair',
      'rewind doctor --repair --dry-run',
      'rewind doctor --json'
    ]
  },
  scrub: {
    usage: 'rewind scrub [--yes] [options]',
    description: 'Redact raw secrets from historical journal and re-seal cryptographic hash chain.',
    arguments: [],
    options: [
      { flag: '--yes, -y', description: 'Confirm scrub without interactive prompt' },
      { flag: '--json', description: 'Output result in JSON format' },
      { flag: '--root <path>', description: 'Explicit project root / ledger directory' }
    ],
    examples: [
      'rewind scrub',
      'rewind scrub --yes'
    ]
  }
};

/**
 * Formats top-level CLI help text.
 *
 * @param {import('../formatter.js').createStyler} s - Styler instance
 * @returns {string}
 */
export function formatTopLevelHelp(s) {
  const lines = [
    `${s.bold('REWIND')} — Remember what fixed it.`,
    `${s.dim('A local verified-recovery ledger for the terminal.')}`,
    '',
    `${s.bold('USAGE:')}`,
    `  ${s.cyan('rewind')} ${s.yellow('<command>')} [options]`,
    '',
    `${s.bold('CORE WORKFLOW:')}`,
    `  1. ${s.cyan('rewind run <command...>')}          Run command, stream output, and record failures on error`,
    `  2. ${s.cyan('rewind history')}                   Browse timeline of past failures and recovery states`,
    `  3. ${s.cyan('rewind show <id>')}                 Inspect full forensic logs, environment, and error fingerprint`,
    `  4. ${s.cyan('rewind triage [id]')}               Interactive 7-step guided recovery triage and verification`,
    `  5. ${s.cyan('rewind recover <id>')}              Record suspected cause, fix, and explicit verification command`,
    `  6. ${s.cyan('rewind verify <id>')}               Run user-approved verification command to validate and seal fix`,
    `  7. ${s.cyan('rewind search <query...>')}         Search past failures by keyword, error text, or fingerprint`,
    `  8. ${s.cyan('rewind patterns')}                  Analyze failure/recovery patterns and flakiness diagnostics`,
    `  9. ${s.cyan('rewind context [latest|<id>]')}     Output structured diagnostic context for coding agents`,
    `  10. ${s.cyan('rewind export-shared')}            Export sanitized recovery bundle for team sharing`,
    `  11. ${s.cyan('rewind import-shared [file]')}     Import verified knowledge from shared recovery bundle`,
    `  12. ${s.cyan('rewind hook <shell>')}             Generate shell hook scripts for bash, zsh, or powershell`,
    `  13. ${s.cyan('rewind doctor')}                   Run installation and ledger self-diagnostics`,
    `  14. ${s.cyan('rewind verify-integrity')}        Audit cryptographic hash chain and checkpoint integrity`,
    `  15. ${s.cyan('rewind rebuild')}                 Reconstruct derived incident views from immutable journal`,
    `  16. ${s.cyan('rewind scrub')}                   Redact raw secrets from journal and re-seal hash chain`,
    '',
    `${s.bold('GLOBAL OPTIONS:')}`,
    `  ${s.yellow('-h, --help')}                        Show help information`,
    `  ${s.yellow('-v, --version')}                     Show version number`,
    `  ${s.yellow('--json')}                            Output results as machine-readable JSON (read-only commands)`,
    `  ${s.yellow('--no-color')}                    Disable ANSI color formatting (also respects NO_COLOR)`,
    `  ${s.yellow('--root <path>')}                 Specify project root / ledger location`,
    `  ${s.yellow('-n, --limit <N>')}               Limit number of results in history and search`,
    '',
    `${s.bold('SAFETY & TRUST INVARIANTS:')}`,
    `  • ${s.dim('Zero Auto-Execution:')} Rewind NEVER automatically executes historical recovery fixes.`,
    `  • ${s.dim('Explicit Verification:')} Verification runs ONLY the command explicitly approved by the user.`,
    `  • ${s.dim('Local & Offline:')} 100% offline, zero network requests, zero telemetry, zero dependencies.`,
    '',
    `${s.bold('LEARN MORE:')}`,
    `  Run ${s.cyan('rewind <command> --help')} or ${s.cyan('rewind help <command>')} for command details.`
  ];

  return lines.join('\n');
}

/**
 * Formats help text for a specific command.
 *
 * @param {string} commandName
 * @param {import('../formatter.js').createStyler} s
 * @returns {string}
 */
export function formatCommandHelp(commandName, s) {
  const doc = COMMAND_DOCS[commandName];
  if (!doc) {
    return formatTopLevelHelp(s);
  }

  const lines = [
    `${s.bold(`REWIND ${commandName.toUpperCase()}`)} — ${doc.description}`,
    '',
    `${s.bold('USAGE:')}`,
    `  ${s.cyan(doc.usage)}`,
    ''
  ];

  if (doc.arguments.length > 0) {
    lines.push(`${s.bold('ARGUMENTS:')}`);
    for (const arg of doc.arguments) {
      lines.push(`  ${s.yellow(arg.name.padEnd(20))} ${arg.description}`);
    }
    lines.push('');
  }

  if (doc.options.length > 0) {
    lines.push(`${s.bold('OPTIONS:')}`);
    for (const opt of doc.options) {
      lines.push(`  ${s.yellow(opt.flag.padEnd(20))} ${opt.description}`);
    }
    lines.push('');
  }

  if (doc.examples.length > 0) {
    lines.push(`${s.bold('EXAMPLES:')}`);
    for (const ex of doc.examples) {
      lines.push(`  ${s.dim('$')} ${ex}`);
    }
    lines.push('');
  }

  return lines.join('\n').trimEnd();
}

/**
 * Handler for the help route.
 */
export async function helpCommand({ commandName = null, context }) {
  const { stdout, styler } = context;
  if (commandName && COMMAND_DOCS[commandName]) {
    stdout.write(formatCommandHelp(commandName, styler) + '\n');
  } else {
    stdout.write(formatTopLevelHelp(styler) + '\n');
  }
  return 0;
}
