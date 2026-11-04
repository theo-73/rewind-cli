import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { readGitMetadata } from './git.js';
import { captureSafeEnvironment } from './environment.js';
import { sanitizeForDisplay, redactRecordForStorage } from './sanitizer.js';
import { SpawnError } from './errors.js';
import { parseDiagnostic } from './diagnostics/index.js';

/**
 * Maximum captured buffer size per stream (10MB) to prevent resource exhaustion.
 */
export const MAX_BUFFER_BYTES = 10 * 1024 * 1024;

/**
 * Resolves an executable command across Windows and POSIX systems.
 * On Windows, searches PATH and PATHEXT to detect if an executable is a .cmd/.bat script
 * that requires Windows shell execution under Node's security model.
 *
 * @param {string} executable
 * @param {string} [cwd=process.cwd()]
 * @param {Record<string, string>} [env=process.env]
 * @returns {{ resolvedExecutable: string, isBatchFile: boolean }}
 */
export function resolveExecutable(executable, cwd = process.cwd(), env = process.env) {
  if (process.platform !== 'win32') {
    return { resolvedExecutable: executable, isBatchFile: false };
  }

  // If executable explicitly ends with .cmd or .bat
  if (/\.(cmd|bat)$/i.test(executable)) {
    const target = executable.includes(' ') && !executable.startsWith('"') ? `"${executable}"` : executable;
    return { resolvedExecutable: target, isBatchFile: true };
  }

  // If executable explicitly ends with .exe or .com
  if (/\.(exe|com)$/i.test(executable)) {
    return { resolvedExecutable: executable, isBatchFile: false };
  }

  // Look up PATH and PATHEXT case-insensitively
  const pathEnvKey = Object.keys(env).find(k => k.toUpperCase() === 'PATH') || 'PATH';
  const pathExtEnvKey = Object.keys(env).find(k => k.toUpperCase() === 'PATHEXT') || 'PATHEXT';

  const pathStr = env[pathEnvKey] || '';
  const pathExtStr = env[pathExtEnvKey] || '.COM;.EXE;.BAT;.CMD';
  const extensions = pathExtStr.split(';').filter(Boolean);

  const searchDirs = [cwd, ...pathStr.split(path.delimiter).filter(Boolean)];

  for (const dir of searchDirs) {
    for (const ext of extensions) {
      const candidate = path.join(dir, `${executable}${ext}`);
      try {
        if (fs.existsSync(candidate)) {
          const isBatch = /\.(cmd|bat)$/i.test(ext);
          // If it's a batch script, passing the original command name with shell: true
          // or quoted path ensures cmd.exe executes it cleanly on Windows
          const target = isBatch
            ? (executable.includes(path.sep) || executable.includes('/')
                ? (candidate.includes(' ') && !candidate.startsWith('"') ? `"${candidate}"` : candidate)
                : executable)
            : candidate;
          return { resolvedExecutable: target, isBatchFile: isBatch };
        }
      } catch {
        // Ignore file access errors
      }
    }
  }

  return { resolvedExecutable: executable, isBatchFile: false };
}

/**
 * Execution and capture result record.
 * @typedef {object} CaptureRecord
 * @property {string} command - Target executable/command
 * @property {string[]} args - Target arguments
 * @property {string} fullCommand - Combined command line string
 * @property {string} cwd - Working directory at execution time
 * @property {string} startTime - ISO timestamp at process start
 * @property {string} endTime - ISO timestamp at process completion
 * @property {number} durationMs - Execution time in milliseconds
 * @property {number|null} exitCode - Exit code (0 for success, non-zero for failure)
 * @property {string|null} signal - Termination signal (e.g. SIGTERM) if killed
 * @property {boolean} success - Whether process exited with code 0 and no signal
 * @property {string} stdoutRaw - Exact raw stdout buffer converted to UTF-8
 * @property {string} stderrRaw - Exact raw stderr buffer converted to UTF-8
 * @property {string} stdout - Sanitized plain-text stdout
 * @property {string} stderr - Sanitized plain-text stderr
 * @property {import('./git.js').GitMetadata} git - Repository HEAD metadata
 * @property {object} environment - Safe platform and environment metadata
 */

const SIGNAL_MAP = {
  SIGHUP: 129,
  SIGINT: 130,
  SIGQUIT: 131,
  SIGKILL: 137,
  SIGUSR1: 138,
  SIGUSR2: 140,
  SIGALRM: 142,
  SIGTERM: 143
};

/**
 * Maps a POSIX termination signal string to standard 128+N exit code.
 *
 * @param {string|null} signal
 * @returns {number|null}
 */
export function mapSignalToExitCode(signal) {
  if (!signal) return null;
  return SIGNAL_MAP[signal] || 128;
}

/**
 * Executes a child process, streams its output live, and captures all lifecycle,
 * output, git, and environment diagnostic evidence with safety limits.
 *
 * @param {string[]} commandTokens - Command and arguments array (e.g. ['npm', 'test'])
 * @param {object} [options]
 * @param {string} [options.cwd=process.cwd()] - Working directory
 * @param {Record<string, string>} [options.env=process.env] - Process environment
 * @param {NodeJS.WritableStream|null} [options.stdoutStream] - Stream to pipe live stdout to
 * @param {NodeJS.WritableStream|null} [options.stderrStream] - Stream to pipe live stderr to
 * @param {boolean} [options.shell] - Whether to spawn inside a shell
 * @param {number} [options.timeout] - Process execution timeout in ms
 * @param {number} [options.maxBufferBytes=MAX_BUFFER_BYTES] - Maximum buffer bytes per stream
 * @returns {Promise<CaptureRecord>}
 */
export async function executeAndCapture(commandTokens, options = {}) {
  if (!commandTokens || !Array.isArray(commandTokens) || commandTokens.length === 0) {
    throw new SpawnError('No command specified for execution.');
  }

  const [executable, ...args] = commandTokens;
  const cwd = options.cwd || process.cwd();
  const env = options.env || process.env;
  const stdoutStream = options.stdoutStream || null;
  const stderrStream = options.stderrStream || null;
  const maxBuffer = options.maxBufferBytes || MAX_BUFFER_BYTES;

  // Prepare child environment: preserve terminal color if TTY is present and NO_COLOR is not active
  const childEnv = { ...env };
  if (!childEnv.NO_COLOR && !process.env.NO_COLOR) {
    if (process.stdout?.isTTY || process.env.FORCE_COLOR !== undefined) {
      if (childEnv.FORCE_COLOR === undefined) {
        childEnv.FORCE_COLOR = '1';
      }
    }
  }

  const { resolvedExecutable, isBatchFile } = resolveExecutable(executable, cwd, childEnv);
  const useShell = options.shell !== undefined ? Boolean(options.shell) : (process.platform === 'win32' && isBatchFile);

  let spawnTarget = resolvedExecutable;
  let spawnArgs = args;

  if (useShell) {
    if (options.shell) {
      // Direct shell command string execution
      if (commandTokens.length === 1) {
        spawnTarget = commandTokens[0];
        spawnArgs = [];
      } else {
        spawnTarget = commandTokens.map(t => (/\s/.test(t) && !t.startsWith('"') && !t.startsWith("'")) ? `"${t.replace(/"/g, '\\"')}"` : t).join(' ');
        spawnArgs = [];
      }
    } else if (args.length > 0 && args.some(a => ['&&', '||', ';', '|', '&', '>', '<'].includes(a))) {
      spawnTarget = commandTokens.map(t => (/\s/.test(t) && !t.startsWith('"') && !t.startsWith("'")) ? `"${t.replace(/"/g, '\\"')}"` : t).join(' ');
      spawnArgs = [];
    }
  }

  const startTimeIso = new Date().toISOString();
  const startHrTime = process.hrtime.bigint();

  const stdoutChunks = [];
  const stderrChunks = [];
  let stdoutBytes = 0;
  let stderrBytes = 0;
  let stdoutTruncated = false;
  let stderrTruncated = false;
  let isTimedOut = false;

  return new Promise((resolve, reject) => {
    let childProcess;
    let timeoutTimer = null;

    try {
      childProcess = spawn(spawnTarget, spawnArgs, {
        cwd,
        env: childEnv,
        shell: useShell,
        stdio: ['inherit', 'pipe', 'pipe']
      });
    } catch (err) {
      return reject(new SpawnError(`Failed to spawn command "${executable}": ${err.message}`, { originalError: err.message }));
    }

    // Forward parent SIGINT and SIGTERM to child process to prevent orphaned processes
    const onSigInt = () => {
      try {
        if (childProcess && !childProcess.killed) {
          childProcess.kill('SIGINT');
        }
      } catch {
        // Ignore kill errors if already terminated
      }
    };

    const onSigTerm = () => {
      try {
        if (childProcess && !childProcess.killed) {
          childProcess.kill('SIGTERM');
        }
      } catch {
        // Ignore kill errors if already terminated
      }
    };

    process.on('SIGINT', onSigInt);
    process.on('SIGTERM', onSigTerm);

    const cleanup = () => {
      process.removeListener('SIGINT', onSigInt);
      process.removeListener('SIGTERM', onSigTerm);
      if (timeoutTimer) {
        clearTimeout(timeoutTimer);
        timeoutTimer = null;
      }
    };

    if (typeof options.timeout === 'number' && options.timeout > 0) {
      timeoutTimer = setTimeout(() => {
        isTimedOut = true;
        try {
          if (childProcess && !childProcess.killed) {
            childProcess.kill('SIGTERM');
          }
        } catch {
          // Ignore
        }
      }, options.timeout);
      timeoutTimer.unref?.();
    }

    if (childProcess.stdout) {
      childProcess.stdout.on('data', (chunk) => {
        if (stdoutBytes < maxBuffer) {
          const remaining = maxBuffer - stdoutBytes;
          if (chunk.length > remaining) {
            stdoutChunks.push(chunk.subarray(0, remaining));
            stdoutBytes += remaining;
            if (!stdoutTruncated) {
              stdoutTruncated = true;
              stdoutChunks.push(Buffer.from(`\n[rewind: output truncated after ${maxBuffer} bytes limit]\n`, 'utf8'));
            }
          } else {
            stdoutChunks.push(chunk);
            stdoutBytes += chunk.length;
          }
        } else if (!stdoutTruncated) {
          stdoutTruncated = true;
          stdoutChunks.push(Buffer.from(`\n[rewind: output truncated after ${maxBuffer} bytes limit]\n`, 'utf8'));
        }

        if (stdoutStream && typeof stdoutStream.write === 'function') {
          stdoutStream.write(chunk);
        }
      });
    }

    if (childProcess.stderr) {
      childProcess.stderr.on('data', (chunk) => {
        if (stderrBytes < maxBuffer) {
          const remaining = maxBuffer - stderrBytes;
          if (chunk.length > remaining) {
            stderrChunks.push(chunk.subarray(0, remaining));
            stderrBytes += remaining;
            if (!stderrTruncated) {
              stderrTruncated = true;
              stderrChunks.push(Buffer.from(`\n[rewind: output truncated after ${maxBuffer} bytes limit]\n`, 'utf8'));
            }
          } else {
            stderrChunks.push(chunk);
            stderrBytes += chunk.length;
          }
        } else if (!stderrTruncated) {
          stderrTruncated = true;
          stderrChunks.push(Buffer.from(`\n[rewind: output truncated after ${maxBuffer} bytes limit]\n`, 'utf8'));
        }

        if (stderrStream && typeof stderrStream.write === 'function') {
          stderrStream.write(chunk);
        }
      });
    }

    let isSettled = false;

    childProcess.on('error', (err) => {
      if (isSettled) return;
      isSettled = true;
      cleanup();
      if (err.code === 'ENOENT') {
        reject(new SpawnError(`Command not found: "${executable}"`, { code: err.code }));
      } else {
        reject(new SpawnError(`Process error for "${executable}": ${err.message}`, { code: err.code }));
      }
    });

    childProcess.on('close', (exitCode, signal) => {
      if (isSettled) return;
      isSettled = true;
      cleanup();
      const endHrTime = process.hrtime.bigint();
      const endTimeIso = new Date().toISOString();
      const durationMs = Number((endHrTime - startHrTime) / 1_000_000n);

      const stdoutRaw = Buffer.concat(stdoutChunks).toString('utf8');
      const stderrRaw = Buffer.concat(stderrChunks).toString('utf8');

      const stdoutSanitized = sanitizeForDisplay(stdoutRaw);
      const stderrSanitized = sanitizeForDisplay(stderrRaw);

      // Safe git and environment metadata
      const gitMetadata = readGitMetadata(cwd);
      const safeEnv = captureSafeEnvironment(env);
      const diagnostic = parseDiagnostic(stderrSanitized || stderrRaw, stdoutSanitized || stdoutRaw, { command: executable, cwd });

      const resolvedExitCode = exitCode !== null ? exitCode : (signal ? mapSignalToExitCode(signal) : 1);

      /** @type {CaptureRecord} */
      const record = {
        command: executable,
        args,
        fullCommand: commandTokens.join(' '),
        cwd,
        startTime: startTimeIso,
        endTime: endTimeIso,
        durationMs,
        exitCode: resolvedExitCode,
        signal: signal || null,
        timedOut: isTimedOut,
        success: exitCode === 0 && signal === null && !isTimedOut,
        stdoutRaw,
        stderrRaw,
        stdout: stdoutSanitized,
        stderr: stderrSanitized,
        diagnostic,
        isTruncated: stdoutTruncated || stderrTruncated,
        git: gitMetadata,
        environment: safeEnv
      };

      resolve(redactRecordForStorage(record));
    });
  });
}
