import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { runCLI } from '../src/cli.js';
import { redactSecrets, sanitizeOutput, stripAnsi } from '../src/sanitizer.js';
import { captureSafeEnvironment } from '../src/environment.js';
import { executeAndCapture, mapSignalToExitCode } from '../src/capture.js';
import { tokenizeCommandLine } from '../src/parser.js';

function createMockIO({ env = {}, isTTY = false, cwd = process.cwd() } = {}) {
  let stdoutData = '';
  let stderrData = '';

  const stdout = {
    write: (chunk) => {
      stdoutData += chunk;
      return true;
    }
  };

  const stderr = {
    write: (chunk) => {
      stderrData += chunk;
      return true;
    }
  };

  return {
    io: {
      stdout,
      stderr,
      stdin: {},
      env,
      isTTY,
      cwd
    },
    getStdout: () => stdoutData,
    getStderr: () => stderrData
  };
}

describe('Security & Command Execution Safety Audit (test/security.test.js)', () => {
  describe('Command Injection & Argument Boundary Immunity', () => {
    test('does not execute shell metacharacters in arguments (pipes, semicolons, redirections)', async () => {
      // If shell: true were used, this would execute subcommands or redirect output.
      // With argument-array execution (shell: false), Node passes the arguments verbatim to the executable.
      const payload = 'foo; echo INJECTED_SEMICOLON | echo INJECTED_PIPE > /tmp/injected_file && calc.exe';
      const result = await executeAndCapture([
        process.execPath,
        '-e',
        'console.log(process.argv[1])',
        payload
      ]);

      assert.equal(result.success, true);
      assert.equal(result.exitCode, 0);
      assert.ok(result.stdout.includes(payload));
    });

    test('preserves arguments containing spaces without splitting', async () => {
      const argWithSpaces = 'arg with multiple embedded spaces and tabs\t';
      const result = await executeAndCapture([
        process.execPath,
        '-e',
        'console.log(JSON.stringify(process.argv.slice(1)))',
        argWithSpaces
      ]);

      assert.equal(result.success, true);
      const parsedArgs = JSON.parse(result.stdout.trim());
      assert.equal(parsedArgs.length, 1);
      assert.equal(parsedArgs[0], argWithSpaces);
    });

    test('preserves quotes and apostrophes in argument values', async () => {
      const quotedArg = '"double quotes" and \'single quotes\' and `backticks`';
      const result = await executeAndCapture([
        process.execPath,
        '-e',
        'console.log(process.argv[1])',
        quotedArg
      ]);

      assert.equal(result.success, true);
      assert.ok(result.stdout.includes(quotedArg));
    });

    test('preserves full Unicode, emojis, and multilingual text in arguments', async () => {
      const unicodeArg = '日本語テキスト 🚀 測試 Unicode ää öö üü 💖 \u00A0 \u200B';
      const result = await executeAndCapture([
        process.execPath,
        '-e',
        'console.log(process.argv[1])',
        unicodeArg
      ]);

      assert.equal(result.success, true);
      assert.ok(result.stdout.includes('日本語テキスト'));
      assert.ok(result.stdout.includes('🚀'));
      assert.ok(result.stdout.includes('測試'));
    });

    test('preserves empty string arguments at beginning, middle, and end', async () => {
      const result = await executeAndCapture([
        process.execPath,
        '-e',
        'console.log(JSON.stringify(process.argv.slice(1)))',
        '',
        'middle-arg',
        ''
      ]);

      assert.equal(result.success, true);
      const parsed = JSON.parse(result.stdout.trim());
      assert.equal(parsed.length, 3);
      assert.equal(parsed[0], '');
      assert.equal(parsed[1], 'middle-arg');
      assert.equal(parsed[2], '');
    });

    test('executes cleanly in directories containing spaces', async () => {
      const tempSpaceDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind space test-'));
      try {
        const result = await executeAndCapture([
          process.execPath,
          '-e',
          'console.log(process.cwd())'
        ], { cwd: tempSpaceDir });

        assert.equal(result.success, true);
        assert.ok(result.stdout.includes('rewind space test-'));
      } finally {
        try { fs.rmSync(tempSpaceDir, { recursive: true, force: true }); } catch {}
      }
    });

    test('tokenizeCommandLine respects quotes, spaces, and escapes', () => {
      const cmd = 'npm test -- --filter "test with spaces" --dir=\'my folder\' --flag';
      const tokens = tokenizeCommandLine(cmd);
      assert.deepEqual(tokens, [
        'npm',
        'test',
        '--',
        '--filter',
        'test with spaces',
        '--dir=my folder',
        '--flag'
      ]);
    });
  });

  describe('Output Attack Protection & Display Sanitization', () => {
    test('neutralizes OSC terminal hyperlinks and window title changes', () => {
      const malicious = '\x1B]8;;https://malicious-site.com\x07Click here\x1B]8;;\x07 \x1B]0;Malicious Title\x07 \x1B[2J\x1B[H';
      const sanitized = sanitizeOutput(malicious);
      assert.ok(!sanitized.includes('\x1B'));
      assert.ok(!sanitized.includes('\x07'));
      assert.ok(!sanitized.includes('Malicious Title'));
      assert.equal(sanitized.trim(), 'Click here');
    });

    test('strips dangerous non-printable ASCII control characters but preserves tabs and newlines', () => {
      const malicious = 'Normal\ttext\nLine 2\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0B\x0C\x0E\x1F\x7F';
      const sanitized = sanitizeOutput(malicious);
      assert.equal(sanitized, 'Normal\ttext\nLine 2');
    });

    test('normalizes carriage-return line overwrite attacks to safe newlines', () => {
      const malicious = 'Secret malicious task started\rNormal status [OK]';
      const sanitized = sanitizeOutput(malicious);
      // \r is converted to \n so neither line is hidden/overwritten in logs
      assert.equal(sanitized, 'Secret malicious task started\nNormal status [OK]');
    });

    test('strips orphan and malformed escape bytes', () => {
      const broken = 'Text with trailing escape \x1B and incomplete \x1B[3';
      const cleaned = stripAnsi(broken);
      assert.ok(!cleaned.includes('\x1B'));
    });
  });

  describe('Secret Redaction Engine', () => {
    test('redacts OpenAI API keys', () => {
      const mockKey = ['sk', 'proj', 'mockexampletoken12345678901234'].join('-');
      const input = `Failed with OpenAI key ${mockKey} in config`;
      const output = redactSecrets(input);
      assert.ok(!output.includes(mockKey));
      assert.ok(output.includes('[REDACTED_API_KEY]'));
    });

    test('redacts GitHub personal access tokens', () => {
      const mockToken = ['ghp', 'mockexamplegithubtoken1234567890'].join('_');
      const input = `Auth error: ${mockToken} is invalid`;
      const output = redactSecrets(input);
      assert.ok(!output.includes(mockToken));
      assert.ok(output.includes('[REDACTED_GITHUB_TOKEN]'));
    });

    test('redacts AWS access keys', () => {
      const mockKey = ['AKIA', '0123456789ABCDEF'].join('');
      const input = `AWS credentials: ${mockKey} rejected`;
      const output = redactSecrets(input);
      assert.ok(!output.includes(mockKey));
      assert.ok(output.includes('[REDACTED_AWS_KEY]'));
    });

    test('redacts Slack tokens', () => {
      const mockToken = ['xoxb', '000000000000', 'mockslacktoken12345678'].join('-');
      const input = `Webhook failed with token ${mockToken}`;
      const output = redactSecrets(input);
      assert.ok(!output.includes(mockToken));
      assert.ok(output.includes('[REDACTED_SLACK_TOKEN]'));
    });

    test('redacts Bearer authorization tokens', () => {
      const mockJwt = ['Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', 'mockpayload', 'mocksignature'].join('.');
      const input = `Header: Authorization: ${mockJwt}`;
      const output = redactSecrets(input);
      assert.ok(!output.includes('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'));
      assert.ok(output.includes('Bearer [REDACTED]'));
    });

    test('redacts PEM private key blocks', () => {
      const input = 'Loaded key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----\nDone.';
      const output = redactSecrets(input);
      assert.ok(!output.includes('MIIEowIBAAKCAQEA0'));
      assert.ok(output.includes('[REDACTED_PRIVATE_KEY]'));
    });

    test('redacts Basic Auth credentials in URLs', () => {
      const input = 'Error connecting to https://admin:superSecretPassword123@db.internal:5432/main';
      const output = redactSecrets(input);
      assert.ok(!output.includes('admin:superSecretPassword123'));
      assert.ok(output.includes('https://[REDACTED]@db.internal:5432/main'));
    });

    test('redacts password key-value parameters', () => {
      const input = 'Connection string: host=localhost;password="superSecret999";user=app';
      const output = redactSecrets(input);
      assert.ok(!output.includes('superSecret999'));
      assert.ok(output.includes('password=[REDACTED]'));
    });
  });

  describe('Privacy & Environment Key Isolation', () => {
    test('never stores sensitive environment variable values', () => {
      const rawEnv = {
        PATH: '/usr/bin',
        NODE_ENV: 'production',
        AWS_SECRET_ACCESS_KEY: 'mockSecretAccessKeyExampleValue',
        GITHUB_TOKEN: 'mockGithubTokenValue1234567890',
        DATABASE_PASSWORD: 'superSecretDatabasePassword'
      };

      const safe = captureSafeEnvironment(rawEnv);
      assert.equal(safe.totalEnvVars, 5);
      // Key names are recorded for reproducibility hashing
      assert.ok(safe.envKeys.includes('AWS_SECRET_ACCESS_KEY'));
      assert.ok(safe.envKeys.includes('GITHUB_TOKEN'));
      assert.ok(safe.envKeys.includes('DATABASE_PASSWORD'));

      // Sensitive values are NEVER stored in safeValues
      assert.equal(safe.safeValues.AWS_SECRET_ACCESS_KEY, undefined);
      assert.equal(safe.safeValues.GITHUB_TOKEN, undefined);
      assert.equal(safe.safeValues.DATABASE_PASSWORD, undefined);

      // Only allowlisted non-sensitive keys have values
      assert.equal(safe.safeValues.NODE_ENV, 'production');
    });
  });

  describe('Resource Exhaustion Protection & Buffer Limits', () => {
    test('caps stream buffers at configured memory limit and marks truncated', async () => {
      const result = await executeAndCapture([
        process.execPath,
        '-e',
        'for (let i = 0; i < 500; i++) { console.log("A".repeat(100)); }'
      ], {
        maxBufferBytes: 2048 // 2KB test cap
      });

      assert.ok(result.stdoutRaw.length < 5000);
      assert.ok(result.stdoutRaw.includes('[rewind: output truncated after 2048 bytes limit]'));
      assert.equal(result.isTruncated, true);
    });

    test('handles extremely long lines (100,000 characters) safely without crashing', async () => {
      const result = await executeAndCapture([
        process.execPath,
        '-e',
        'console.log("X".repeat(100000))'
      ]);

      assert.equal(result.success, true);
      assert.ok(result.stdoutRaw.length >= 100000);
      assert.equal(result.stdout.length >= 100000, true);
    });
  });

  describe('Timeout, Signal Handling & Process Lifetime', () => {
    test('distinguishes execution timeout from regular non-zero exit code', async () => {
      const result = await executeAndCapture([
        process.execPath,
        '-e',
        'setTimeout(() => console.log("done"), 5000)'
      ], {
        timeout: 100 // 100ms timeout
      });

      assert.equal(result.success, false);
      assert.equal(result.timedOut, true);
      assert.equal(result.exitCode !== 0, true);
    });

    test('mapSignalToExitCode maps standard POSIX signals to 128+N exit codes', () => {
      assert.equal(mapSignalToExitCode('SIGINT'), 130);
      assert.equal(mapSignalToExitCode('SIGTERM'), 143);
      assert.equal(mapSignalToExitCode('SIGKILL'), 137);
      assert.equal(mapSignalToExitCode('SIGHUP'), 129);
      assert.equal(mapSignalToExitCode('UNKNOWN_SIGNAL'), 128);
      assert.equal(mapSignalToExitCode(null), null);
    });
  });

  describe('Path Traversal & ID Sanitization', () => {
    test('rejects path traversal attempts in show command', async () => {
      const mock1 = createMockIO();
      const code1 = await runCLI(['show', '../../etc/passwd'], mock1.io);
      assert.equal(code1, 1);
      assert.ok(mock1.getStderr().includes('Incident #../../etc/passwd not found in ledger'));

      const mock2 = createMockIO();
      const code2 = await runCLI(['show', '1/../../../etc'], mock2.io);
      assert.equal(code2, 1);
    });

    test('rejects path traversal attempts in recover command', async () => {
      const mock = createMockIO();
      const code = await runCLI(['recover', '../../1', '--cause', 'hack'], mock.io);
      assert.equal(code, 1);
    });

    test('rejects path traversal attempts in verify command', async () => {
      const mock = createMockIO();
      const code = await runCLI(['verify', '../1', '--yes'], mock.io);
      assert.equal(code, 1);
    });
  });

  describe('Command Argument Redaction & Storage Hygiene', () => {
    test('redacts secrets in command flags and arguments before saving to journal and store', async () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-sec-args-'));
      try {
        const rootFlag = `--root=${tmpDir}`;
        const secretToken = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        const mock = createMockIO({ cwd: tmpDir });
        await runCLI([
          rootFlag,
          'run',
          process.execPath,
          '-e',
          'console.error("fail"); process.exit(1);',
          '--token',
          secretToken
        ], mock.io);

        // Read journal.jsonl
        const journalPath = path.join(tmpDir, '.rewind', 'journal.jsonl');
        assert.ok(fs.existsSync(journalPath));
        const journalContent = fs.readFileSync(journalPath, 'utf8');
        assert.equal(journalContent.includes(secretToken), false, 'Raw token must not appear in journal');
        assert.ok(journalContent.includes('[REDACTED]') || journalContent.includes('[REDACTED_GITHUB_TOKEN]'));
      } finally {
        try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
      }
    });

    test('rejects trivial verification commands to enforce red-to-green proof', async () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-sec-trivial-'));
      try {
        const rootFlag = `--root=${tmpDir}`;
        const mock1 = createMockIO({ cwd: tmpDir });
        await runCLI([rootFlag, 'run', process.execPath, '-e', 'console.error("fail"); process.exit(1);'], mock1.io);

        const mock2 = createMockIO({ cwd: tmpDir });
        const code2 = await runCLI([
          rootFlag,
          'recover',
          '1',
          '--change',
          'fake fix',
          '--verify-cmd',
          'true'
        ], mock2.io);

        assert.equal(code2, 2);
        assert.ok(mock2.getStderr().includes('trivial'));
      } finally {
        try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
      }
    });

    test('rewind verify requires --yes in non-interactive sessions', async () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-sec-confirm-'));
      try {
        const rootFlag = `--root=${tmpDir}`;
        const mock1 = createMockIO({ cwd: tmpDir });
        await runCLI([rootFlag, 'run', process.execPath, '-e', 'console.error("fail"); process.exit(1);'], mock1.io);

        const mock2 = createMockIO({ cwd: tmpDir });
        await runCLI([
          rootFlag,
          'recover',
          '1',
          '--change',
          'real fix',
          '--verify-cmd',
          `"${process.execPath}" -e "process.exit(0);"`
        ], mock2.io);

        // Attempt verify without --yes in non-interactive mode
        const mock3 = createMockIO({ cwd: tmpDir, isTTY: false });
        const code3 = await runCLI([rootFlag, 'verify', '1'], mock3.io);
        assert.notEqual(code3, 0);
        assert.ok(mock3.getStderr().includes('Confirmation required'));
      } finally {
        try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
      }
    });

    test('rewind scrub sanitizes raw secrets from journal and re-seals hash chain', async () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-sec-scrub-'));
      try {
        const rootFlag = `--root=${tmpDir}`;
        const mock1 = createMockIO({ cwd: tmpDir });
        await runCLI([rootFlag, 'run', process.execPath, '-e', 'console.error("fail"); process.exit(1);'], mock1.io);

        const mockScrub = createMockIO({ cwd: tmpDir });
        const scrubCode = await runCLI([rootFlag, 'scrub', '--yes'], mockScrub.io);
        assert.equal(scrubCode, 0);
        assert.ok(mockScrub.getStdout().includes('RE-SEAL'));

        const mockDoctor = createMockIO({ cwd: tmpDir });
        const doctorCode = await runCLI([rootFlag, 'doctor'], mockDoctor.io);
        assert.equal(doctorCode, 0);
      } finally {
        try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
      }
    });
  });
});
