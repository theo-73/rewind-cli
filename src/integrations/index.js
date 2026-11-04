import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { installCursorIntegration } from './cursor.js';
import { installGeminiIntegration } from './gemini.js';
import { installCodexIntegration } from './codex.js';
import { installClaudeIntegration } from './claude.js';

export {
  installCursorIntegration,
  installGeminiIntegration,
  installCodexIntegration,
  installClaudeIntegration
};

/**
 * Detects agent environments present in the given workspace root or user system.
 *
 * @param {string} [rootDir=process.cwd()]
 * @param {object} [options]
 * @param {boolean} [options.checkUser] - Whether to check user profile directories (~/.cursor, ~/.gemini, etc.)
 * @param {boolean} [options.checkEnv] - Whether to check environment variables
 * @returns {{ cursor: boolean, gemini: boolean, codex: boolean, claude: boolean, detected: string[], details: object }}
 */
export function detectAgentEnvironments(rootDir = process.cwd(), options = {}) {
  const isCwd = path.resolve(rootDir) === path.resolve(process.cwd());
  const checkUser = typeof options.checkUser === 'boolean' ? options.checkUser : isCwd;
  const checkEnv = typeof options.checkEnv === 'boolean' ? options.checkEnv : isCwd;
  const detected = [];
  const homeDir = os.homedir?.() || process.env.HOME || process.env.USERPROFILE || '';

  // 1. Detect Cursor
  const hasCursorDir = fs.existsSync(path.join(rootDir, '.cursor'));
  const hasCursorRules = fs.existsSync(path.join(rootDir, '.cursorrules'));
  const hasCursorEnv = checkEnv && Boolean(process.env.CURSOR_TRACE_DIR || process.env.CURSOR_PROJECT_DIR);
  const hasCursorUser = checkUser && Boolean(homeDir && fs.existsSync(path.join(homeDir, '.cursor')));
  const isCursor = hasCursorDir || hasCursorRules || hasCursorEnv || hasCursorUser;
  if (isCursor) detected.push('Cursor');

  // 2. Detect Gemini
  const hasGeminiDir = fs.existsSync(path.join(rootDir, '.gemini'));
  const hasGeminiEnv = checkEnv && Boolean(process.env.GEMINI_CLI || process.env.GEMINI_PROJECT_DIR);
  const hasGeminiUser = checkUser && Boolean(homeDir && fs.existsSync(path.join(homeDir, '.gemini')));
  const isGemini = hasGeminiDir || hasGeminiEnv || hasGeminiUser;
  if (isGemini) detected.push('Gemini');

  // 3. Detect Codex
  const hasCodexDir = fs.existsSync(path.join(rootDir, '.codex'));
  const hasCodexEnv = checkEnv && Boolean(process.env.CODEX_PROJECT_DIR);
  const hasCodexUser = checkUser && Boolean(homeDir && fs.existsSync(path.join(homeDir, '.codex')));
  const isCodex = hasCodexDir || hasCodexEnv || hasCodexUser;
  if (isCodex) detected.push('Codex');

  // 4. Detect Claude Code
  const hasClaudeDir = fs.existsSync(path.join(rootDir, '.claude'));
  const hasClaudeConfig = fs.existsSync(path.join(rootDir, 'CLAUDE.md')) || fs.existsSync(path.join(rootDir, '.claude', 'settings.json'));
  const hasClaudeEnv = checkEnv && Boolean(process.env.CLAUDE_PROJECT_DIR || process.env.CLAUDE_CODE);
  const hasClaudeUser = checkUser && Boolean(homeDir && fs.existsSync(path.join(homeDir, '.claude')));
  const isClaude = hasClaudeDir || hasClaudeConfig || hasClaudeEnv || hasClaudeUser;
  if (isClaude) detected.push('Claude');

  return {
    cursor: isCursor,
    gemini: isGemini,
    codex: isCodex,
    claude: isClaude,
    detected,
    details: {
      cursor: { project: hasCursorDir || hasCursorRules, user: hasCursorUser, env: hasCursorEnv },
      gemini: { project: hasGeminiDir, user: hasGeminiUser, env: hasGeminiEnv },
      codex: { project: hasCodexDir, user: hasCodexUser, env: hasCodexEnv },
      claude: { project: hasClaudeDir || hasClaudeConfig, user: hasClaudeUser, env: hasClaudeEnv }
    }
  };
}

/**
 * Installs integration hooks for all detected agent environments.
 *
 * @param {string} rootDir
 * @param {object} [options]
 * @returns {{ installed: string[], filesCreated: string[] }}
 */
export function installAllDetected(rootDir, options = {}) {
  const envs = detectAgentEnvironments(rootDir, options);
  const installed = [];
  const filesCreated = [];

  const targetAgent = options.agent ? String(options.agent).trim().toLowerCase() : null;

  if (targetAgent) {
    if (targetAgent === 'cursor') {
      const res = installCursorIntegration(rootDir, options);
      installed.push('Cursor');
      filesCreated.push(...res.filesCreated);
    } else if (targetAgent === 'gemini') {
      const res = installGeminiIntegration(rootDir, options);
      installed.push('Gemini');
      filesCreated.push(...res.filesCreated);
    } else if (targetAgent === 'codex') {
      const res = installCodexIntegration(rootDir, options);
      installed.push('Codex');
      filesCreated.push(...res.filesCreated);
    } else if (targetAgent === 'claude') {
      const res = installClaudeIntegration(rootDir, options);
      installed.push('Claude');
      filesCreated.push(...res.filesCreated);
    }
    return { installed, filesCreated };
  }

  // Install integrations ONLY for detected agent environments (no silent fallback)
  if (envs.cursor) {
    const res = installCursorIntegration(rootDir, options);
    installed.push('Cursor');
    filesCreated.push(...res.filesCreated);
  }

  if (envs.gemini) {
    const res = installGeminiIntegration(rootDir, options);
    installed.push('Gemini');
    filesCreated.push(...res.filesCreated);
  }

  if (envs.codex) {
    const res = installCodexIntegration(rootDir, options);
    installed.push('Codex');
    filesCreated.push(...res.filesCreated);
  }

  if (envs.claude) {
    const res = installClaudeIntegration(rootDir, options);
    installed.push('Claude');
    filesCreated.push(...res.filesCreated);
  }

  return {
    installed,
    filesCreated
  };
}
