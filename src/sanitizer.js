/**
 * Output sanitizer, terminal escape stripper, and conservative secret redactor.
 */

// Matches ANSI escape codes (CSI, OSC, DCS, APC, PM, and 2-byte escapes)
const OSC_PATTERN = /\x1B\][^\x07\x1B]*(?:\x07|\x1B\\)/g;
const DCS_APC_PATTERN = /\x1B[P^_][^\x1B]*(?:\x1B\\|\x07)/g;
const CSI_PATTERN = /\x1B\[[0-9;?]*[ -/]*[@-~]/g;
const ESC_SINGLE_PATTERN = /\x1B[@-Z\\-_]/g;

// Matches non-printable control characters excluding \t, \n, \r
const CONTROL_CHARS_PATTERN = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;

// Secret Patterns
const PEM_PRIVATE_KEY_PATTERN = /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----/gi;
const OPENAI_KEY_PATTERN = /\bsk-[a-zA-Z0-9_-]{20,}\b/g;
const GITHUB_TOKEN_PATTERN = /\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{20,}\b/g;
const AWS_KEY_PATTERN = /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g;
const SLACK_TOKEN_PATTERN = /\bxox[baprs]-[0-9a-zA-Z-]{15,}\b/g;
const BEARER_TOKEN_PATTERN = /\bBearer\s+[a-zA-Z0-9_\-\.]{15,}\b/gi;
const BASIC_AUTH_URL_PATTERN = /([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)[^:\s\/@]+:[^@\s\/]+@/gi;
// Note: We use {4,} here to avoid false positives on legitimate single-character config values like `DEBUG=1`, `VERBOSE=0`
const KEY_VALUE_SECRET_PATTERN = /\b(password|passwd|secret|api[_-]?key|auth[_-]?token|client[_-]?secret|private[_-]?key)\s*[:=]\s*(?:(['"])(.+?)\2|([^\s'",;&]{3,}))/gi;

/**
 * Strips ANSI escape sequences from a string.
 *
 * @param {string} str
 * @returns {string}
 */
export function stripAnsi(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(OSC_PATTERN, '')
    .replace(DCS_APC_PATTERN, '')
    .replace(CSI_PATTERN, '')
    .replace(ESC_SINGLE_PATTERN, '')
    .replace(/\x1B/g, '');
}

/**
 * Redacts common secret formats (API keys, private keys, bearer tokens, passwords)
 * using conservative regex patterns.
 *
 * Note: Regex redaction reduces accidental leakage of standard token formats in logs,
 * but cannot guarantee 100% detection of arbitrary user secrets.
 *
 * @param {string} text
 * @returns {string}
 */
export function redactSecrets(text) {
  if (typeof text !== 'string') return '';

  return text
    .replace(PEM_PRIVATE_KEY_PATTERN, '[REDACTED_PRIVATE_KEY]')
    .replace(OPENAI_KEY_PATTERN, '[REDACTED_API_KEY]')
    .replace(GITHUB_TOKEN_PATTERN, '[REDACTED_GITHUB_TOKEN]')
    .replace(AWS_KEY_PATTERN, '[REDACTED_AWS_KEY]')
    .replace(SLACK_TOKEN_PATTERN, '[REDACTED_SLACK_TOKEN]')
    .replace(BEARER_TOKEN_PATTERN, 'Bearer [REDACTED]')
    .replace(BASIC_AUTH_URL_PATTERN, '$1[REDACTED]@')
    .replace(KEY_VALUE_SECRET_PATTERN, '$1=[REDACTED]');
}

/**
 * Sanitizes untrusted terminal output for safe storage and display.
 * - Strips ANSI escape sequences
 * - Strips non-printable control characters
 * - Normalizes line breaks to LF (\n)
 *
 * @param {string} str
 * @returns {string}
 */
export function sanitizeOutput(str) {
  if (str === null || str === undefined) return '';
  const text = String(str);

  return stripAnsi(text)
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .replace(CONTROL_CHARS_PATTERN, '');
}

/**
 * Sanitizes and redacts untrusted output specifically for terminal rendering.
 *
 * @param {string} str
 * @returns {string}
 */
export function sanitizeForDisplay(str) {
  return redactSecrets(sanitizeOutput(str));
}

/**
 * Flag-aware argument redactor for command line argument arrays.
 * Redacts secrets in flag=value formats and values immediately following sensitive flags.
 *
 * @param {string[]} args
 * @returns {string[]}
 */
export function redactCommandArgs(args) {
  if (!Array.isArray(args)) return [];
  const sensitiveFlags = new Set([
    '--token',
    '--password',
    '--passwd',
    '--secret',
    '--api-key',
    '--apikey',
    '--api_key',
    '--auth-token',
    '--access-token',
    '--client-secret',
    '--private-key',
    '-p'
  ]);

  const result = [];
  for (let i = 0; i < args.length; i++) {
    const raw = args[i];
    if (typeof raw !== 'string') {
      result.push(raw);
      continue;
    }
    const arg = raw;

    // Check if previous argument was a sensitive flag expecting a value
    if (i > 0) {
      const prev = String(args[i - 1]).toLowerCase();
      if (sensitiveFlags.has(prev) && !arg.startsWith('-')) {
        result.push('[REDACTED]');
        continue;
      }
    }

    // Check for flag=value syntax (e.g. --token=secret or --password=secret)
    const eqIdx = arg.indexOf('=');
    if (eqIdx !== -1) {
      const flagPart = arg.slice(0, eqIdx).toLowerCase();
      if (sensitiveFlags.has(flagPart) || /password|secret|token|api[_-]?key/i.test(flagPart)) {
        result.push(`${arg.slice(0, eqIdx)}=[REDACTED]`);
        continue;
      }
    }

    // Check for attached short flag e.g. -pSECRET
    if (arg.startsWith('-p') && arg.length > 2 && !arg.startsWith('-p=')) {
      result.push('-p[REDACTED]');
      continue;
    }

    // Apply standard pattern redaction to individual token
    result.push(redactSecrets(arg));
  }
  return result;
}

/**
 * Flag-aware command string redactor for full command lines.
 *
 * @param {string} cmdStr
 * @returns {string}
 */
export function redactCommandString(cmdStr) {
  if (!cmdStr || typeof cmdStr !== 'string') return '';
  let result = redactSecrets(cmdStr);

  // Redact key=value or key:value forms for sensitive flags
  result = result.replace(
    /(--?(?:token|password|passwd|secret|api[_-]?key|auth[_-]?token|access[_-]?token|client[_-]?secret)\s*[:=]\s*)(?:(['"])(.*?)\2|([^\s'"]+))/gi,
    '$1[REDACTED]'
  );

  // Redact space-separated flag values
  result = result.replace(
    /(\s+(?:--token|--password|--passwd|--secret|--api-key|--apikey|--api_key|--auth-token|--access-token|--client-secret|-p)\s+)(?:(['"])(.*?)\2|([^\s\-\\/][^\s]*))/gi,
    '$1[REDACTED]'
  );

  return result;
}

/**
 * Redacts an execution/incident record completely before persistence to journal or SQLite.
 * Ensures command, args, fullCommand, stdout, and stderr are never stored with raw secrets.
 *
 * @param {object} record
 * @returns {object}
 */
export function redactRecordForStorage(record) {
  if (!record || typeof record !== 'object') return record;
  const command = record.command ? redactSecrets(record.command) : '';
  const args = redactCommandArgs(record.args || []);
  let fullCommand = record.fullCommand ? redactCommandString(record.fullCommand) : '';
  if (!fullCommand && (command || args.length > 0)) {
    fullCommand = [command, ...args].filter(Boolean).join(' ');
  }

  const rawStdout = record.stdoutRaw || record.stdout || '';
  const rawStderr = record.stderrRaw || record.stderr || '';

  return {
    ...record,
    command,
    args,
    fullCommand,
    stdout: redactSecrets(record.stdout || ''),
    stderr: redactSecrets(record.stderr || ''),
    stdoutRaw: redactSecrets(rawStdout),
    stderrRaw: redactSecrets(rawStderr)
  };
}

/**
 * Redacts secrets from an MCP tool execution result.
 *
 * @param {object} toolResult
 * @returns {object}
 */
export function redactMcpResult(toolResult) {
  if (!toolResult || typeof toolResult !== 'object') return toolResult;
  if (Array.isArray(toolResult.content)) {
    return {
      ...toolResult,
      content: toolResult.content.map((item) => {
        if (item && item.type === 'text' && typeof item.text === 'string') {
          return { ...item, text: redactSecrets(item.text) };
        }
        return item;
      })
    };
  }
  return toolResult;
}

/**
 * Checks whether a verification command is trivial (e.g., "true", "exit 0", ":").
 * Trivial commands do not prove a fix and must be rejected.
 *
 * @param {string} cmd
 * @returns {boolean}
 */
export function isTrivialVerifyCommand(cmd) {
  if (!cmd || typeof cmd !== 'string') return true;
  const normalized = cmd.trim().toLowerCase().replace(/^["']|["']$/g, '').trim();
  const trivialCommands = new Set([
    'true',
    ':',
    'exit 0',
    'exit',
    'false',
    '/bin/true',
    '/usr/bin/true',
    'return 0',
    'echo ok',
    'echo pass',
    'cmd /c exit 0',
    'cmd.exe /c exit 0'
  ]);
  if (trivialCommands.has(normalized)) return true;
  if (/^(?:exit\s+0|cmd(?:\.exe)?\s+\/c\s+exit\s+0)$/i.test(normalized)) return true;
  return false;
}

