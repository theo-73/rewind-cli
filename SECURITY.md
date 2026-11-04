# Security & Privacy Architecture

REWIND is designed with strict security, privacy, and threat-mitigation principles for developer terminals.

---

## 1. Zero-Telemetry & Privacy Invariants

- **100% Offline & Local:** Rewind does not make outbound network calls, connect to remote servers, or transmit data over the network.
- **No External AI APIs or Cloud Databases:** No failure logs, code snippets, or environment metadata are ever transmitted to third-party AI or cloud services.
- **Zero Third-Party Runtime Dependencies:** Rewind is built purely using the Node.js standard library with zero runtime packages, eliminating supply chain risks.

---

## 2. Threat Model & Mitigations

| Threat Vector | Mitigation Strategy |
| :--- | :--- |
| **Command Injection in Execution** | Arguments are passed as discrete argument arrays directly to `node:child_process.spawn` with `shell: false`. No string concatenation into implicit shell strings. Metacharacters (`|`, `;`, `&`, `$()`, `>`, `<`) are treated as literal strings. |
| **Path Traversal Attacks** | Strict integer or hex-hash validation (`/^\d+$/` or `^[a-f0-9]{16}$` / `^[a-f0-9]{64}$`) on all incident IDs and fingerprints. Absolute path resolution with `path.resolve()` on root ledger options. Null-byte and relative traversal patterns (`../`) rejected fail-closed. |
| **Terminal ANSI & Title Attacks** | All captured `stdout`/`stderr` text is treated as untrusted evidence. ANSI color escapes, OSC window title sequences, cursor jump sequences, control characters, and trailing orphan escape bytes are stripped before display (`sanitizeForDisplay()`). |
| **Terminal Line Overwrite Spoofing** | Carriage-return sequences (`\r\n`, `\r`) are normalized to `\n` at the display boundary to neutralize terminal line overwrite spoofing attacks. |
| **Resource Exhaustion (DoS)** | Memory buffer capped at 10MB per stream (`MAX_BUFFER_BYTES`) during process capture to prevent heap overflow from infinite logging loops. Extremely long lines (100,000+ chars) handled safely. |
| **Orphaned Child Processes** | Parent-to-child signal forwarding (`SIGINT`, `SIGTERM`) ensures child processes are cleanly terminated when the CLI exits or times out. |
| **Secret & Credential Leakage** | Conservative regex redaction for API keys (OpenAI, GitHub, AWS, Slack), PEM private key headers, Bearer tokens, Basic Auth URLs, and password parameters. Environment variables are captured as names only (with strict allowlist for `NODE_ENV`, `CI`, `LANG`, `TZ`). Raw secrets are never persisted in `journal.jsonl` or `.rewind/evidence/`. Historical entries can be sanitized and re-sealed using `rewind scrub`. |
| **Command Injection in Fixes** | Rewind **never** executes verification commands through MCP. The `rewind_request_verification` MCP tool returns a verification plan for host/user approval without executing anything. Verification commands execute ONLY through explicit user initiation (`rewind verify <id>` CLI command) with `shell: false` by default, interactive confirmation, and requiring `--yes` in non-interactive sessions. Host integrations own execution approval. |
| **Shell Hook Side-Effects** | Shell hooks are purely passive observers. The original exit code (`$?` / `$LASTEXITCODE`) is strictly preserved under all conditions. All hook failures are silenced (`catch {}` / `2>/dev/null`) to guarantee user terminal workflows are never interrupted. |
| **Shared Recovery Bundle Poisoning** | Imported bundles are **never automatically trusted locally**. Imported verified fixes are explicitly marked `VERIFIED — EXTERNAL EVIDENCE` (Quality: `SUPPORTED`) and disqualified from confident surfacing until explicitly re-verified locally by running `rewind verify <id>`. Machine-specific paths and local identifiers are stripped before export. |
| **Corrupt / Malicious Records** | Schema-invalid or malformed JSON records are automatically quarantined into `.rewind/quarantine/` without crashing the CLI. Authoritative `journal.jsonl` is tamper-evident via cryptographic SHA-256 hash chaining. |
| **File Permissions & Concurrency** | Storage directories use `0o700` and record files use `0o600` file permissions. Exclusive lock file (`journal.lock`) with PID liveness verification prevents concurrent append corruption. |

---

## 3. Process Execution & Cross-Platform Invariants

1. **Strict Argument-Array Execution:**
   - In `src/capture.js`, execution tokens are separated into `[executable, ...args]`.
   - On POSIX systems, `spawn(executable, args, { shell: false })` invokes `execve` directly without invoking `/bin/sh` or `/bin/bash`.
   - On Windows, `resolveExecutable` inspects `PATH` and `PATHEXT`. If a Windows batch script (`.cmd` or `.bat`) is targeted, it applies quotes to paths containing spaces under Node's security model (CVE-2024-27980); native `.exe` binaries execute with `shell: false`.
2. **Signal Forwarding & Standard Exit Codes:**
   - Termination signals are mapped to standard POSIX `128+N` codes (`SIGINT` = 130, `SIGTERM` = 143, `SIGKILL` = 137).
   - Execution timeouts (`--timeout`) are recorded as distinct events with `timedOut: true` rather than masquerading as clean command failure.
3. **Storage & Display Sanitization:**
   - Captured process outputs have credentials and secrets redacted prior to persistence in `.rewind/evidence/` and `journal.jsonl`.
   - Sanitization, ANSI escape code stripping, and secret filtering are additionally enforced at the display boundary (`sanitizeForDisplay()`).
4. **Shell Hook & Sharing Invariants:**
   - Shell hooks never rewrite or replace the user's shell, and never run in non-interactive sessions (`!isTTY`).
   - Bundle exports scrub absolute user paths (`/Users/alice/...`, `C:\Users\bob\...`), machine IDs, and unallowlisted environment keys before writing shareable files. No `git` CLI executable is ever invoked.

---

## 4. Secret Redaction Limitations

Rewind applies conservative pattern matching for common secret formats (e.g., standard API token prefixes, PEM headers, URL credentials). 

> **Important Limitation:** Heuristic regex redaction reduces accidental leakage in terminal displays and logs, but cannot mathematically guarantee detection of arbitrary or custom secrets. Users should ensure their command outputs do not emit unencrypted private keys or proprietary secrets.

---

## 5. Reporting Security Vulnerabilities

To report a vulnerability, please open a private GitHub security advisory on the repository.
