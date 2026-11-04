# Zero-Dependency Verification Guide (`DEPENDENCY_PROOF.md`)

This guide provides fast, reproducible commands for developers and security auditors to verify Rewind's **Zero Third-Party Dependency** architecture.

---

## 1. Verify `package.json` Dependencies

Run the following command in the repository root:

```bash
node -e "const pkg = require('./package.json'); console.log('Runtime dependencies:', pkg.dependencies || {}); console.log('Dev dependencies:', pkg.devDependencies || {});"
```

**Expected Output:**
```text
Runtime dependencies: {}
Dev dependencies: {}
```

---

## 2. Verify Zero `node_modules` Directory

Verify that no third-party code is vendored or installed:

```bash
# On Linux/macOS
test ! -d node_modules && echo "PASSED: No node_modules folder exists"

# On Windows (PowerShell)
if (-not (Test-Path node_modules)) { Write-Host "PASSED: No node_modules folder exists" }
```

---

## 3. Verify Runtime Imports in `src/`

Scan all JavaScript source files in `src/` to confirm that every import statement targets either a Node.js standard library built-in (`node:*`) or an internal relative module (`./*` or `../*`):

```bash
# On Linux/macOS
grep -rn "^import " src/ bin/

# On Windows (PowerShell)
Get-ChildItem -Path src,bin -Filter *.js -Recurse | Select-String -Pattern "^import "
```

**Audit Result:**
Every single import in the codebase maps to:
- `node:fs`
- `node:path`
- `node:child_process`
- `node:crypto`
- `node:os`
- `node:stream`
- `node:readline`
- `node:sqlite`
- Relative files (`./*.js`, `../*.js`)

---

## 4. Verify Zero Network & Zero Outbound HTTP

Check for any networking or HTTP client modules across `src/`:

```bash
# Search for network modules (http, https, net, fetch, dgram)
# On Linux/macOS
grep -rnE "(from 'node:http|from 'node:https|from 'node:net|fetch\(|WebSocket)" src/

# On Windows (PowerShell)
Get-ChildItem -Path src -Filter *.js -Recurse | Select-String -Pattern "(node:http|node:https|node:net|fetch\(|WebSocket)"
```

**Expected Output:** Zero results found.

---

## 5. Run Automated Tests with Zero Installed Packages

Run the complete test suite directly from a clean clone without running `npm install`:

```bash
node --test
```

**Expected Output:**
```text
# tests 497
# suites 111
# pass 497
# fail 0
# cancelled 0
# skipped 0
# todo 0
```
