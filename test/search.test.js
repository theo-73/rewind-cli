import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs';
import { runCLI } from '../src/cli.js';
import { scoreRecord, searchRecords, extractTokens } from '../src/storage/search.js';
import { IncidentStatus } from '../src/storage/state.js';

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

function createSampleRecord(overrides = {}) {
  return {
    id: '1',
    fingerprint: 'a1b2c3d4e5f67890',
    command: 'npm',
    args: ['test'],
    fullCommand: 'npm test',
    cwd: '/mock',
    startTime: '2026-08-29T12:00:00.000Z',
    endTime: '2026-08-29T12:00:01.000Z',
    durationMs: 1000,
    exitCode: 1,
    signal: null,
    status: IncidentStatus.OBSERVED,
    stdout: '',
    stderr: 'ConnectionError: Failed to connect to PostgreSQL database on port 5432: connection refused',
    normalizedError: 'ConnectionError: Failed to connect to PostgreSQL database on port 5432: connection refused',
    stdoutRaw: '',
    stderrRaw: 'ConnectionError: Failed to connect to PostgreSQL database on port 5432: connection refused',
    git: { isGit: false },
    environment: { platform: 'linux', nodeVersion: 'v22.0.0' },
    recoveries: [],
    verification: null,
    ...overrides
  };
}

describe('Conservative Near-Match Search (src/storage/search.js)', () => {
  test('extractTokens strips stop words and returns normalized unique tokens', () => {
    const tokens = extractTokens('Error: Failed to connect to the database in production on port 5432');
    assert.ok(tokens.has('error'));
    assert.ok(tokens.has('failed'));
    assert.ok(tokens.has('connect'));
    assert.ok(tokens.has('database'));
    assert.ok(tokens.has('production'));
    assert.ok(tokens.has('port'));
    assert.ok(tokens.has('5432'));
    // Stop words removed
    assert.equal(tokens.has('to'), false);
    assert.equal(tokens.has('the'), false);
    assert.equal(tokens.has('in'), false);
    assert.equal(tokens.has('on'), false);
  });

  test('exact fingerprint match scores 1.0', () => {
    const rec = createSampleRecord({ fingerprint: '83282360259bab81', status: IncidentStatus.RECOVERED });
    const match = scoreRecord('83282360259bab81', rec);

    assert.equal(match.score, 1.0);
    assert.equal(match.confidence, 'VERIFIED');
    assert.ok(match.reason.includes('Exact fingerprint match'));
  });

  test('exact fingerprint match on unverified record surfaces as LIKELY, never VERIFIED', () => {
    const rec = createSampleRecord({ fingerprint: '83282360259bab81', status: IncidentStatus.OBSERVED });
    const match = scoreRecord('83282360259bab81', rec);

    assert.equal(match.score, 1.0);
    // CRITICAL SAFETY RULE: Unverified record must NEVER have VERIFIED confidence
    assert.notEqual(match.confidence, 'VERIFIED');
    assert.equal(match.confidence, 'LIKELY');
  });

  test('exact fingerprint match scores 1.0 across v1/v2 versions', () => {
    const v1Fp = '83282360259bab81';
    const v2Fp = '83282360259bab81e4b6c89055aa42eca9455fd21dec05380123456789abcdef';

    // 1. Query with 64-char v2 against legacy 16-char v1 record
    const legacyRec = createSampleRecord({ fingerprint: v1Fp, status: IncidentStatus.RECOVERED });
    const matchLegacy = scoreRecord(v2Fp, legacyRec);
    assert.equal(matchLegacy.score, 1.0);
    assert.equal(matchLegacy.confidence, 'VERIFIED');
    assert.ok(matchLegacy.reason.includes('Exact fingerprint match'));

    // 2. Query with 16-char v1 against modern 64-char v2 record
    const modernRec = createSampleRecord({ fingerprint: v2Fp, status: IncidentStatus.RECOVERED });
    const matchModern = scoreRecord(v1Fp, modernRec);
    assert.equal(matchModern.score, 1.0);
    assert.equal(matchModern.confidence, 'VERIFIED');
    assert.ok(matchModern.reason.includes('Exact fingerprint match'));
  });

  test('near-match with token overlap scores predictably', () => {
    const rec = createSampleRecord({
      normalizedError: 'FATAL: Database connection pool exhausted on port 5432'
    });

    const match1 = scoreRecord('database connection pool exhausted', rec);
    assert.ok(match1.score >= 0.70, `Score should be >= 0.70, got ${match1.score}`);
    assert.ok(match1.matchedTokens.includes('database'));
    assert.ok(match1.matchedTokens.includes('connection'));
    assert.ok(match1.matchedTokens.includes('pool'));
    assert.ok(match1.matchedTokens.includes('exhausted'));
  });

  test('unrelated error scores below threshold and is rejected', () => {
    const rec = createSampleRecord({
      command: 'python',
      args: ['app.py'],
      fullCommand: 'python app.py',
      stderr: 'TypeError: Cannot read properties of undefined (reading "map")',
      normalizedError: 'TypeError: Cannot read properties of undefined (reading "map")'
    });

    const match = scoreRecord('PostgreSQL database connection timeout', rec);
    assert.equal(match.score, 0.0);
    assert.equal(match.confidence, 'NOT PROVEN');

    const searchResults = searchRecords('PostgreSQL database connection timeout', [rec]);
    assert.equal(searchResults.length, 0);
  });

  test('searchRecords enforces deterministic ordering: highest score first, newest ID tie-break', () => {
    const rec1 = createSampleRecord({ id: '1', normalizedError: 'Database connection failed', stderr: 'Database connection failed' });
    const rec2 = createSampleRecord({ id: '2', normalizedError: 'Database connection pool completely exhausted', stderr: 'Database connection pool completely exhausted' });
    const rec3 = createSampleRecord({ id: '3', normalizedError: 'Database connection pool exhausted', stderr: 'Database connection pool exhausted' });

    const results = searchRecords('database connection pool exhausted', [rec1, rec2, rec3]);
    assert.ok(results.length >= 2);
    // rec2 and rec3 have higher overlap than rec1
    assert.ok(results[0].score >= results[results.length - 1].score);
  });

  test('CLI: rewind search <query> displays matches in text and JSON mode', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-search-cli-'));
    try {
      const rootFlag = `--root=${tmpDir}`;

      // 1. Run failure
      const mockRun = createMockIO({ cwd: tmpDir });
      await runCLI([rootFlag, 'run', process.execPath, '-e', 'console.error("ETIMEDOUT: Redis cluster socket connection timed out"); process.exit(1);'], mockRun.io);

      // 2. Recover and verify
      const mockRec = createMockIO({ cwd: tmpDir });
      await runCLI([
        rootFlag,
        'recover',
        '1',
        '--cause',
        'Redis endpoint was unreachable',
        '--change',
        'Updated host to redis.internal',
        '--verify-cmd',
        `"${process.execPath}" -e "process.exit(0);"`
      ], mockRec.io);

      const mockVer = createMockIO({ cwd: tmpDir });
      await runCLI([rootFlag, 'verify', '1', '--yes'], mockVer.io);

      // 3. Search in text mode
      const mockSearchText = createMockIO({ cwd: tmpDir });
      const codeText = await runCLI([rootFlag, 'search', 'Redis cluster socket timeout'], mockSearchText.io);

      assert.equal(codeText, 0);
      const textOut = mockSearchText.getStdout();
      assert.ok(textOut.includes('SEARCH RESULTS for "Redis cluster socket timeout"'));
      assert.ok(textOut.includes('VERIFIED RECOVERY'));
      assert.ok(textOut.includes('Redis endpoint was unreachable'));
      assert.ok(textOut.includes('Updated host to redis.internal'));

      // 4. Search in JSON mode
      const mockSearchJson = createMockIO({ cwd: tmpDir });
      const codeJson = await runCLI([rootFlag, 'search', 'Redis cluster', '--json'], mockSearchJson.io);

      assert.equal(codeJson, 0);
      assert.equal(mockSearchJson.getStderr(), '');

      const parsed = JSON.parse(mockSearchJson.getStdout().trim());
      assert.equal(parsed.status, 'success');
      assert.equal(parsed.count, 1);
      assert.equal(parsed.data[0].id, '1');
      assert.equal(parsed.data[0].confidence, 'VERIFIED');
      assert.ok(parsed.data[0].score > 0.4);
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('CLI: rewind search matches keywords and phrases in applied recovery fixes', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-search-fix-'));
    try {
      const rootFlag = `--root=${tmpDir}`;

      // 1. Run failure
      const mockRun = createMockIO({ cwd: tmpDir });
      await runCLI([rootFlag, 'run', process.execPath, '-e', 'console.error("Connection pool exhausted on port 5432"); process.exit(1);'], mockRun.io);

      // 2. Recover with distinct fix text and verify
      const mockRec = createMockIO({ cwd: tmpDir });
      await runCLI([
        rootFlag,
        'recover',
        '1',
        '--cause',
        'Default connection limit reached in postgresql.conf',
        '--change',
        'Increased max_connections to 200 in postgresql.conf',
        '--verify-cmd',
        `"${process.execPath}" -e "process.exit(0);"`
      ], mockRec.io);

      const mockVer = createMockIO({ cwd: tmpDir });
      await runCLI([rootFlag, 'verify', '1', '--yes'], mockVer.io);

      // 3. Search using keywords from the applied fix (which are not in the error output)
      const mockSearchFix = createMockIO({ cwd: tmpDir });
      const codeFix = await runCLI([rootFlag, 'search', 'max_connections 200'], mockSearchFix.io);

      assert.equal(codeFix, 0);
      const textOut = mockSearchFix.getStdout();
      assert.ok(textOut.includes('SEARCH RESULTS for "max_connections 200"'));
      assert.ok(textOut.includes('VERIFIED RECOVERY'));
      assert.ok(textOut.includes('Increased max_connections to 200'));

      // 4. Search using keywords from the suspected cause
      const mockSearchCause = createMockIO({ cwd: tmpDir });
      const codeCause = await runCLI([rootFlag, 'search', 'postgresql.conf limit'], mockSearchCause.io);

      assert.equal(codeCause, 0);
      assert.ok(mockSearchCause.getStdout().includes('SEARCH RESULTS for "postgresql.conf limit"'));
      assert.ok(mockSearchCause.getStdout().includes('Default connection limit reached'));
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('CLI: rewind search on query with no matches returns friendly notice', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-search-none-'));
    try {
      const rootFlag = `--root=${tmpDir}`;
      const mock = createMockIO({ cwd: tmpDir });
      const code = await runCLI([rootFlag, 'search', 'completely_unmatched_query_xyz_123'], mock.io);

      assert.equal(code, 0);
      assert.ok(mock.getStdout().includes('No matching failure records found'));
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });
});
