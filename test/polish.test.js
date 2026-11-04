import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createStyler, formatRelativeTime, formatStatusBadge, formatBox } from '../src/formatter.js';
import { runCLI } from '../src/cli.js';

function createMockIO({ env = {}, isTTY = false, cwd = process.cwd(), columns = 80 } = {}) {
  let stdoutData = '';
  let stderrData = '';

  const stdout = {
    columns,
    write: (chunk) => {
      stdoutData += chunk;
      return true;
    }
  };

  const stderr = {
    columns,
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

describe('Product Polish & Visual Hierarchy (test/polish.test.js)', () => {
  describe('Relative Time Formatter', () => {
    const base = new Date('2026-08-29T12:00:00.000Z');

    test('formats recent times accurately', () => {
      assert.equal(formatRelativeTime(new Date(base.getTime() - 20 * 1000).toISOString(), base), 'just now');
      assert.equal(formatRelativeTime(new Date(base.getTime() - 75 * 1000).toISOString(), base), '1m ago');
      assert.equal(formatRelativeTime(new Date(base.getTime() - 15 * 60 * 1000).toISOString(), base), '15m ago');
      assert.equal(formatRelativeTime(new Date(base.getTime() - 2 * 3600 * 1000).toISOString(), base), '2h ago');
      assert.equal(formatRelativeTime(new Date(base.getTime() - 3 * 86400 * 1000).toISOString(), base), '3d ago');
    });

    test('handles missing or invalid timestamp gracefully', () => {
      assert.equal(formatRelativeTime(null), 'unknown');
      assert.equal(formatRelativeTime(undefined), 'unknown');
    });
  });

  describe('Semantic Status Badges', () => {
    test('renders distinct badges without color enabled', () => {
      const styler = createStyler(false);
      assert.equal(formatStatusBadge('VERIFIED', styler), 'VERIFIED');
      assert.equal(formatStatusBadge('REGRESSED', styler), 'REGRESSED');
      assert.equal(formatStatusBadge('FIXED', styler), 'FIXED');
      assert.equal(formatStatusBadge('SUSPECTED', styler), 'SUSPECTED');
      assert.equal(formatStatusBadge('OBSERVED', styler), 'OBSERVED');
    });

    test('renders colored badges when color enabled', () => {
      const styler = createStyler(true);
      assert.ok(formatStatusBadge('VERIFIED', styler).includes('\x1b[32m'));
      assert.ok(formatStatusBadge('REGRESSED', styler).includes('\x1b[31m'));
      assert.ok(formatStatusBadge('FIXED', styler).includes('\x1b[36m'));
      assert.ok(formatStatusBadge('SUSPECTED', styler).includes('\x1b[33m'));
    });
  });

  describe('Restrained Box Card Formatter', () => {
    test('formats clean boxed card', () => {
      const styler = createStyler(false);
      const box = formatBox('✓ RECOVERY VERIFIED', [
        { label: 'Incident', value: '#12' },
        { label: 'Command', value: 'npm test' },
        { label: 'Exit Code', value: '0' }
      ], styler, 'success');

      assert.ok(box.startsWith('┌─'));
      assert.ok(box.includes('✓ RECOVERY VERIFIED'));
      assert.ok(box.includes('Incident:              #12'));
      assert.ok(box.endsWith('─┘'));
    });

    test('maintains identical border widths even when color codes are present in values', () => {
      const styler = createStyler(true);
      const box = formatBox('✓ RECOVERY VERIFIED', [
        { label: 'Incident', value: styler.bold('#12') },
        { label: 'Command', value: styler.cyan('npm test') },
        { label: 'Exit Code', value: styler.green('0 (Success)') }
      ], styler, 'success');

      const lines = box.split('\n');
      const firstLineLen = lines[0].length;
      // All lines should have the same visual length when stripped of ANSI codes
      for (const line of lines) {
        assert.equal(styler.visibleLength(line), firstLineLen);
      }
    });
  });

  describe('CLI Display Verification under NO_COLOR', () => {
    test('history output contains no ANSI escapes under NO_COLOR', async () => {
      const mock = createMockIO({ env: { NO_COLOR: '1' } });
      await runCLI(['history'], mock.io);
      const out = mock.getStdout();
      assert.ok(!out.includes('\x1b['));
    });

    test('help output contains no ANSI escapes under NO_COLOR', async () => {
      const mock = createMockIO({ env: { NO_COLOR: '1' } });
      await runCLI(['--help'], mock.io);
      const out = mock.getStdout();
      assert.ok(!out.includes('\x1b['));
      assert.ok(out.includes('REWIND — Remember what fixed it.'));
      assert.ok(out.includes('CORE WORKFLOW:'));
      assert.ok(out.includes('rewind export-shared'));
      assert.ok(out.includes('rewind import-shared'));
      assert.ok(out.includes('rewind hook'));
      assert.ok(out.includes('SAFETY & TRUST INVARIANTS:'));
    });
  });

  describe('Flexible ID Normalization', () => {
    test('supports #id and RW-id formats across show, recover, and verify', async () => {
      const os = await import('node:os');
      const fs = await import('node:fs');
      const path = await import('node:path');
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-norm-test-'));

      try {
        const rootFlag = `--root=${tmpDir}`;

        // 1. Create a failure (id 1)
        const mockRun = createMockIO({ cwd: tmpDir });
        await runCLI([rootFlag, 'run', process.execPath, '-e', 'process.exit(1);'], mockRun.io);

        // 2. Show with #1 and RW-1
        const mockShowHash = createMockIO({ cwd: tmpDir });
        const codeShowHash = await runCLI([rootFlag, 'show', '#1'], mockShowHash.io);
        assert.equal(codeShowHash, 0);
        assert.ok(mockShowHash.getStdout().includes('INCIDENT #1'));

        const mockShowRw = createMockIO({ cwd: tmpDir });
        const codeShowRw = await runCLI([rootFlag, 'show', 'RW-1'], mockShowRw.io);
        assert.equal(codeShowRw, 0);
        assert.ok(mockShowRw.getStdout().includes('INCIDENT #1'));

        // 3. Recover with RW-1
        const mockRecover = createMockIO({ cwd: tmpDir });
        const codeRecover = await runCLI([
          rootFlag,
          'recover',
          'RW-1',
          '--cause',
          'Misconfiguration',
          '--change',
          'Updated settings',
          '--verify-cmd',
          `"${process.execPath}" -e "process.exit(0);"`
        ], mockRecover.io);
        assert.equal(codeRecover, 0);
        assert.ok(mockRecover.getStdout().includes('RECOVERY RECORDED'));

        // 4. Verify with #1
        const mockVerify = createMockIO({ cwd: tmpDir });
        const codeVerify = await runCLI([rootFlag, 'verify', '#1', '--yes'], mockVerify.io);
        assert.equal(codeVerify, 0);
        assert.ok(mockVerify.getStdout().includes('RECOVERY VERIFIED'));
      } finally {
        try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
      }
    });
  });

  describe('Responsive Terminal Width Handling', () => {
    test('history layout adapts gracefully to narrow 60-column terminal', async () => {
      const os = await import('node:os');
      const fs = await import('node:fs');
      const path = await import('node:path');
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-narrow-test-'));

      try {
        const rootFlag = `--root=${tmpDir}`;
        const mockRun = createMockIO({ cwd: tmpDir });
        await runCLI([rootFlag, 'run', process.execPath, '-e', 'process.exit(1);'], mockRun.io);

        const mockHist = createMockIO({ cwd: tmpDir, columns: 60 });
        const code = await runCLI([rootFlag, 'history'], mockHist.io);
        assert.equal(code, 0);
        const out = mockHist.getStdout();
        assert.ok(out.includes('ID'));
        assert.ok(out.includes('STATUS'));
        assert.ok(out.includes('COMMAND'));
        assert.ok(out.includes('TIME'));
        assert.ok(out.includes('RESULT'));
      } finally {
        try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
      }
    });

    test('history layout expands on wide 120-column terminal', async () => {
      const os = await import('node:os');
      const fs = await import('node:fs');
      const path = await import('node:path');
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-wide-test-'));

      try {
        const rootFlag = `--root=${tmpDir}`;
        const mockRun = createMockIO({ cwd: tmpDir });
        await runCLI([rootFlag, 'run', process.execPath, '-e', 'process.exit(1);'], mockRun.io);

        const mockHist = createMockIO({ cwd: tmpDir, columns: 120 });
        const code = await runCLI([rootFlag, 'history'], mockHist.io);
        assert.equal(code, 0);
        const out = mockHist.getStdout();
        assert.ok(out.includes('REWIND RECOVERY LEDGER'));
      } finally {
        try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
      }
    });
  });

  describe('Zero-Dependency Verification', () => {
    test('package.json has zero runtime and dev dependencies', async () => {
      const fs = await import('node:fs');
      const path = await import('node:path');
      const pkgPath = path.resolve('package.json');
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));

      assert.equal(pkg.dependencies, undefined);
      assert.equal(pkg.devDependencies, undefined);
    });
  });
});
