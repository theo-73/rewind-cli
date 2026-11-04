<div align="center">
  <h1>⏪ Rewind CLI</h1>
  <p><strong>Verified Failure Memory for Coding Agents</strong></p>

  [![npm version](https://img.shields.io/npm/v/rewind-cli.svg?color=blue&style=flat-square)](https://www.npmjs.com/package/rewind-cli)
  [![CI Build](https://img.shields.io/github/actions/workflow/status/Tejas3479/rewind-cli/ci.yml?branch=main&style=flat-square)](https://github.com/Tejas3479/rewind-cli/actions)
  [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](https://opensource.org/licenses/MIT)
  [![Node.js >=22.13.0](https://img.shields.io/badge/node-%3E%3D22.13.0-green.svg?style=flat-square)](https://nodejs.org)
  [![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg?style=flat-square)](https://www.npmjs.com/package/rewind-cli)

  <br />
  <em>Stop coding agents from looping on identical failures. Evidence-qualified failure memory, negative hypothesis tracking, and disciplined abstention.</em>
</div>

---

## ⚡ The Problem: Agent Amnesia & Debugging Loops

When coding agents (Claude, Cursor, Codex, Gemini) hit a project-specific failure, they repeatedly fall into known traps:
1. **Looping through already-disproven hypotheses** because they have no negative memory of what failed earlier in the session or in past commits.
2. **Re-inventing fragile workarounds** for errors that were already solved and verified by a developer weeks ago.
3. **Context window bloat** caused by generic memory dumps that inject paragraphs of irrelevant terminal noise on every prompt.

**Rewind** solves this with **evidence-qualified failure memory + selective recall + disciplined abstention**:
* **Evidence Before Memory:** A fix is not canon until it passes a verified test command (`exit 0`).
* **Negative Memory:** Remembers disproven fixes so agents never attempt the same bad change twice.
* **Disciplined Abstention:** If no qualified, compatible remedy exists, Rewind stays completely silent (`SILENCE`). No hallucinations, no prompt noise.
* **Zero Host Risk:** Rewind never executes arbitrary commands inside MCP or background hooks. Verification commands require explicit host/user approval.

---

## ✨ Core Architecture

```
Terminal / Agent Failure
         │
         ▼
┌──────────────────┐
│  Capture Policy  │ ──► [Ctrl+C / 130] ───────────────► DISCARD
│  Classification  │ ──► [Transient / Typo / 127] ─────► OBSERVE (30m TTL cache)
└────────┬─────────┘ ──► [Test Failure / Stack Trace] ──► PROMOTE
         │
         ▼
┌──────────────────┐
│ Ledger & Journal │ ◄── SHA-256 sealed append-only JSONL + SQLite projection
└────────┬─────────┘
         │
         ▼
┌──────────────────┐     ┌────────────────────────────────────────────────────────┐
│ Surfacing Engine │ ──► │ SURFACE: Compatible verified fix exists                │
│ (Abstention Gate)│ ──► │ CAUTION: Stale environment drift or known failed fixes │
└──────────────────┘     │ SILENCE: Abstain (no noise if no qualified fix)        │
                         └────────────────────────────────────────────────────────┘
```

### 1. 3-Tier Capture Policy
Rewind filters noise before it touches your permanent ledger:
- **`DISCARD`**: User cancellations (Ctrl+C / SIGINT 130) are immediately dropped.
- **`OBSERVE`**: Missing commands (127), typos, and transient slips enter a lightweight 30-minute rolling observation cache. If they recur within 30 minutes, they are promoted.
- **`PROMOTE`**: Test runner failures (`pytest`, `npm test`, `cargo test`, `jest`, `vitest`), compiler diagnostics (`file:line`), runtime stack traces, and OOM kills (137) are immediately promoted to the forensic ledger.

### 2. Selective Recall & Abstention
Rewind does not dump full terminal logs on your agent. On recurring commands, it evaluates:
- **Environment compatibility**: Did the compiler version, Node version, or git branch drift?
- **Disproven approaches**: Did a previous attempt with this hypothesis fail?
- **Decision outcome**:
  - `SURFACE`: Emits a concise 1-2 line reminder of the verified fix.
  - `CAUTION`: Warns against known failed attempts or warns of environment drift.
  - `SILENCE`: Produces zero output if no qualified remedy exists.

### 3. Safe Verification Protocol
- Historical fixes store a deterministic verification command (`verifyCmd`).
- The MCP tool `rewind_request_verification` returns a structured verification plan (`REQUIRES_HOST_APPROVAL`) with `readOnlyHint: true` and `openWorldHint: false`.
- Rewind **never** autonomously executes verification commands through MCP. Verification execution is strictly mediated by the host or triggered manually via `rewind verify <id>`.

---

## 🚀 Quick Start

### 1. Installation
Install globally via npm:
```bash
npm install -g rewind-cli
```

### 2. Guided Setup
In your project repository, run:
```bash
rewind setup
```
This automatically:
- Inspects your workspace and detects active coding agents (**Cursor**, **Gemini CLI**, **Codex CLI**, **Claude Code**).
- Configures ambient post-tool failure hooks (`.cursor/hooks.json`, `.gemini/settings.json`, `.codex/hooks.json`, `.claude/settings.json`) and root-safe bridge scripts.
- Installs zero-crash fail-open handlers that output native envelopes without prompt or terminal clutter.
- Supports interactive confirmation with `--yes` (`-y`) flag for scripted automation.

*(To preview configuration changes without writing any files, run `rewind setup --dry-run`)*.

---

## 🤖 AI Agent Integration

### MCP Server
Rewind exposes a high-performance, zero-dependency [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server.

Start the server:
```bash
rewind mcp
```

#### Profiles: Core vs Full
To save agent context tokens, use `--profile core` to expose only the 4 essential failure-recovery tools:
```bash
rewind mcp --profile core
```
* **Core Profile (4 tools):**
  - `rewind_context`: Fetch forensic diagnostic context, verified remedies, and failed approaches.
  - `rewind_recover`: Submit a proposed hypothesis, fix, and verification command.
  - `rewind_request_verification`: Request host-approved verification plan (safe; does not execute).
  - `rewind_search`: Query past failures and fixes by keyword or error snippet.
* **Full Profile (8 tools):** Adds `rewind_history`, `rewind_doctor`, `rewind_patterns`, and `rewind_show`.

#### Claude Desktop Configuration
Add to `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "rewind": {
      "command": "npx",
      "args": ["-y", "rewind-cli", "mcp", "--profile", "core"],
      "env": {
        "REWIND_ROOT": "/absolute/path/to/your/project"
      }
    }
  }
}
```

#### Cursor Integration
Add to `.cursor/mcp.json`:
```json
{
  "mcpServers": {
    "rewind": {
      "command": "npx",
      "args": ["-y", "rewind-cli", "mcp", "--profile", "core"]
    }
  }
}
```

### Ambient Agent Event Gateway
Agents can pipe tool execution failure payloads directly into Rewind via standard input:
```bash
rewind event --json < event.json
# or
rewind event --json --data '{"event":"postToolUseFailure","command":"npm test","exitCode":1,"error":"AssertionError"}'
```
Supports event schemas from **Cursor** (`postToolUseFailure`), **Gemini CLI** (`AfterTool`), **Codex** (`PostToolUse`), and generic JSON. Outputs structured `additionalContext` for immediate agent feedback.

---

## 💻 CLI Reference

| Category | Command | Description |
| :--- | :--- | :--- |
| **Execution** | `rewind run <cmd...>` | Execute command with passive failure capture and quiet surfacing |
| | `rewind event --json` | Ingest ambient agent tool execution events via stdin or flags |
| **Ledger** | `rewind history` | View failure records and recovery timeline |
| | `rewind show <id>` | Inspect forensic failure snapshot, logs, environment, and diffs |
| | `rewind search <query>` | Search historical failures by error text, keyword, or fingerprint |
| **Remediation** | `rewind triage [id]` | Interactive 7-step guided recovery triage and verification wizard |
| | `rewind recover <id>` | Record suspected cause, remediation change, and verify command |
| | `rewind verify <id>` | Execute host-approved verification command to seal remedy to `VERIFIED` |
| | `rewind patterns` | Analyze historical failures for flakiness, regression, and recurring patterns |
| **Agent / IDE** | `rewind setup` | Guided automated setup for Cursor, Gemini, Codex, and MCP |
| | `rewind mcp` | Start Model Context Protocol stdio server (`--profile core\|full`) |
| | `rewind context [id]` | Query structured forensic diagnostic context for agents |
| | `rewind hook <shell>` | Generate non-intrusive shell hooks (`bash`, `zsh`, `powershell`, `fish`) |
| **Integrity** | `rewind doctor` | Run ledger health check and cryptographic chain validation (`--repair`) |
| | `rewind verify-integrity`| Cryptographic SHA-256 audit across append-only journal |
| | `rewind clear` | Safely wipe local ledger storage |

---

## 🛡️ Security & Privacy Invariants

1. **Zero External Dependencies:** Built entirely with Node.js standard libraries and Node's native SQLite engine. No supply-chain bloat.
2. **Automatic Secret Redaction:** API keys, AWS tokens, bearer credentials, and environment passwords are automatically scrubbed from captured logs and memory snapshots before storage.
3. **No Unsanitized Auto-Execution:** Rewind will **never** automatically execute historical commands. Verification commands are executed only through explicit host/user initiation (`rewind verify <id>`).
4. **100% Local Storage:** Everything lives inside your local `.rewind` directory. No telemetry, no external API calls, no third-party data leaks.

---

## 📄 License
MIT © Tejas
