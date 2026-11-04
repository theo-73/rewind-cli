import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs';
import { readGitMetadata } from '../src/git.js';

describe('Zero-Dependency Git Metadata Reader (src/git.js)', () => {
  test('reads git metadata accurately when repository structure exists', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-git-fixture-'));
    try {
      const gitDir = path.join(tmpDir, '.git');
      fs.mkdirSync(path.join(gitDir, 'refs', 'heads'), { recursive: true });
      fs.writeFileSync(path.join(gitDir, 'HEAD'), 'ref: refs/heads/main\n');
      const fakeCommit = 'a1b2c3d4e5f60123456789abcdef0123456789ab';
      fs.writeFileSync(path.join(gitDir, 'refs', 'heads', 'main'), `${fakeCommit}\n`);

      const meta = readGitMetadata(tmpDir);
      assert.equal(meta.isGit, true);
      assert.ok(meta.gitDir);
      assert.equal(meta.workingTreeState, 'unverified');
      assert.equal(meta.branch, 'main');
      assert.equal(meta.headCommit, fakeCommit);
      assert.match(meta.headCommit, /^[0-9a-f]{40}$|^[0-9a-f]{64}$/i);
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('resolves loose ref from mock git repository', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-git-test-'));
    try {
      const gitDir = path.join(tmpDir, '.git');
      fs.mkdirSync(path.join(gitDir, 'refs', 'heads'), { recursive: true });
      fs.writeFileSync(path.join(gitDir, 'HEAD'), 'ref: refs/heads/feature-xyz\n');
      const fakeCommit = 'abcdef0123456789abcdef0123456789abcdef01';
      fs.writeFileSync(path.join(gitDir, 'refs', 'heads', 'feature-xyz'), `${fakeCommit}\n`);

      const meta = readGitMetadata(tmpDir);
      assert.equal(meta.isGit, true);
      assert.equal(meta.ref, 'refs/heads/feature-xyz');
      assert.equal(meta.branch, 'feature-xyz');
      assert.equal(meta.headCommit, fakeCommit);
      assert.equal(meta.detached, false);
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('resolves packed-refs from mock git repository', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-packed-test-'));
    try {
      const gitDir = path.join(tmpDir, '.git');
      fs.mkdirSync(gitDir, { recursive: true });
      fs.writeFileSync(path.join(gitDir, 'HEAD'), 'ref: refs/heads/release-1.0\n');
      const fakeCommit = '1122334455667788990011223344556677889900';
      fs.writeFileSync(
        path.join(gitDir, 'packed-refs'),
        `# pack-refs with: peeled-tags\n${fakeCommit} refs/heads/release-1.0\n`
      );

      const meta = readGitMetadata(tmpDir);
      assert.equal(meta.isGit, true);
      assert.equal(meta.ref, 'refs/heads/release-1.0');
      assert.equal(meta.branch, 'release-1.0');
      assert.equal(meta.headCommit, fakeCommit);
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('resolves detached HEAD directly from 40-character SHA', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-detached-test-'));
    try {
      const gitDir = path.join(tmpDir, '.git');
      fs.mkdirSync(gitDir, { recursive: true });
      const fakeCommit = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
      fs.writeFileSync(path.join(gitDir, 'HEAD'), `${fakeCommit}\n`);

      const meta = readGitMetadata(tmpDir);
      assert.equal(meta.isGit, true);
      assert.equal(meta.detached, true);
      assert.equal(meta.headCommit, fakeCommit);
      assert.equal(meta.ref, null);
      assert.equal(meta.branch, null);
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('handles .git pointer file (worktrees / submodules)', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-worktree-test-'));
    try {
      const actualGitDir = path.join(tmpDir, 'main-repo', '.git', 'worktrees', 'sub');
      const worktreeDir = path.join(tmpDir, 'worktree-sub');

      fs.mkdirSync(actualGitDir, { recursive: true });
      fs.mkdirSync(worktreeDir, { recursive: true });

      const fakeCommit = '9988776655443322110099887766554433221100';
      fs.writeFileSync(path.join(actualGitDir, 'HEAD'), `${fakeCommit}\n`);
      fs.writeFileSync(path.join(worktreeDir, '.git'), `gitdir: ${actualGitDir}\n`);

      const meta = readGitMetadata(worktreeDir);
      assert.equal(meta.isGit, true);
      assert.equal(meta.headCommit, fakeCommit);
      assert.equal(meta.detached, true);
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('returns non-git fallback structure when no .git directory exists', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rewind-nogit-'));
    try {
      const meta = readGitMetadata(tmpDir);
      assert.equal(meta.isGit, false);
      assert.equal(meta.headCommit, null);
      assert.equal(meta.ref, null);
      assert.equal(meta.branch, null);
      assert.equal(meta.workingTreeState, 'unverified');
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });
});
