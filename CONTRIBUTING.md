# Contributing to Rewind

Thank you for your interest in contributing to **Rewind**! We welcome contributions, bug reports, documentation improvements, and feature proposals.

---

## 🔒 The Non-Negotiable Rule: Zero Dependencies

Rewind is built with **100% standard library built-ins** and **ZERO third-party runtime or development dependencies**.

When contributing:
1. **Never add third-party dependencies** to `package.json` (`dependencies` and `devDependencies` must remain strictly empty `{}`).
2. Use Node.js standard built-ins (`node:fs`, `node:path`, `node:crypto`, `node:child_process`, `node:os`, `node:readline`, `node:stream`, `node:assert`, `node:sqlite`).
3. Document any new standard library package replacements in [`STDLIB.md`](./STDLIB.md).

---

## 🛠️ Development Setup

No `npm install` is needed. You only need **Node.js >= 22.5.0**:

```bash
# 1. Clone the repository
git clone https://github.com/theo-73/rewind-cli.git
cd rewind-cli

# 2. Run the test suite
npm test
# (or directly: node --test)

# 3. Verify zero dependencies
npm run check

# 4. Verify deterministic reproducible build
npm run build
npm run verify:build
```

---

## 🧪 Testing Guidelines

Rewind maintains rigorous test coverage using the native Node.js test runner (`node:test`) and assertion library (`node:assert/strict`):

* Every new feature or bugfix **must include automated unit/integration tests** in `test/`.
* All tests must execute cleanly with `node --test` without timeouts or flaky failures.
* Tests should clean up any temporary directories or ledger test files in `afterEach` / `after` hooks.

---

## 📝 Pull Request Process

1. Fork the repository and create a new feature branch (`git checkout -b feat/your-feature`).
2. Implement your changes adhering to standard ES module conventions.
3. Add comprehensive tests in `test/`.
4. Run the entire test suite and verify all tests pass:
   ```bash
   npm test
   npm run build
   npm run verify:build
   ```
5. Open a Pull Request referencing any relevant issues.

---

## 💬 Community & Questions

If you have questions, feel free to open a discussion or file an issue on GitHub.
Please review our [Code of Conduct](./CODE_OF_CONDUCT.md) before participating.
