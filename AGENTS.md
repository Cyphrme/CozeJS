# Project Agent Configuration

## Predicate System

This project uses [predicate](https://github.com/nrdxp/predicate) for agent configuration.

> [!IMPORTANT]
> You **must** review [.agent/PREDICATE.md](.agent/PREDICATE.md) and follow its instructions before beginning work.

**Active Personas:**

- **typescript.md** — JavaScript idioms and patterns (this is a plain JS project, not TypeScript, but the JS conventions apply)
- **depmap.md** — DepMap MCP server usage
- **personalization.md** — User naming and communication preferences

---

## Project Overview

**CozJs** is the official JavaScript implementation of the [Coz](https://github.com/Cyphrme/Coz) cryptographic JSON messaging specification. Coz defines a human-readable, JSON-native signing and verification protocol built on defined cipher suites (`alg`). CozJs implements Coz core for browser environments using the W3C SubtleCrypto API.

The Go reference implementation ([Cyphrme/Coz](https://github.com/Cyphrme/Coz)) is the canonical specification source. CozJs must maintain behavioral parity with the Go implementation for all supported algorithms. **This implementation is currently behind the Coz 1.0 spec and is being updated to reach parity.**

> [!NOTE]
> The project was formerly named "Coze" / "CozeJS". The spec has been renamed to **Coz** to avoid an SEO conflict. Use "Coz" and "CozJs" in all new work.

**Supported algorithms:** ES256, ES384, ES512 (via SubtleCrypto). ES224 is omitted because the W3C WebCryptoAPI excludes P-224.

---

## Build & Commands

CozJs uses **esbuild** to bundle ESM modules into distributable files. No npm-based build pipeline — the build script uses esbuild directly.

- **Build core:** `esbuild join.js --bundle --format=esm --platform=browser --minify --sourcemap --outfile=coze.min.js`
- **Build all (core + extensions):** `cd all && esbuild join_all.js --bundle --format=esm --platform=browser --minify --sourcemap --outfile=coze_all.min.js`
- **Build standard:** `cd standard && esbuild join_standard.js --bundle --format=esm --platform=browser --minify --sourcemap --outfile=coze_standard.min.js`
- **Full build:** `./BUILD.sh` (requires `$COZEJS` env var set to the repo root)
- **Run verifier locally:** `cd verifier && go run server.go` → `https://localhost:8082/coze.html`
- **Run tests locally:** `cd verifier/browsertest && go run server.go` → `https://localhost:8082`

> [!NOTE]
> esbuild can be installed via `go install github.com/evanw/esbuild/cmd/esbuild@v0.15.8` or from [esbuild's installation docs](https://esbuild.github.io/getting-started/#build-from-source).

---

## Code Style

- **Pure ESM:** All source files use ES module `export`/`import` syntax. No CommonJS.
- **No build framework:** No webpack, vite, or npm scripts. esbuild bundles `join.js` (the single entry point).
- **No TypeScript:** Plain JavaScript. No `.ts` files, no `tsconfig.json`.
- **Prefer `const`** over `let`. Never use `var`.
- **Naming:** Follow existing conventions — lowercase module names (`alg.js`, `canon.js`, `key.js`), camelCase for functions and variables.
- **No external runtime dependencies.** Cryptographic primitives come from the browser's SubtleCrypto API.

---

## Architecture

CozJs is structured as a flat set of ESM modules bundled via a join file:

| File           | Purpose                                               |
| :------------- | :---------------------------------------------------- |
| `canon.js`     | Canonicalization — field ordering and canonical forms |
| `alg.js`       | Algorithm definitions — cipher suite parameter sets   |
| `coze.js`      | Core signing, verification, and coz object operations |
| `key.js`       | Key generation, thumbprint computation, revocation    |
| `cryptokey.js` | W3C CryptoKey conversion and SubtleCrypto integration |
| `typedef.js`   | JSDoc type definitions for Coz objects                |
| `join.js`      | Entry point — re-exports all core modules for esbuild |

**Build variants:**

- `coze.min.js` — Core only (via `join.js`)
- `all/coze_all.min.js` — Core + extensions
- `standard/coze_standard.min.js` — Standard subset

**Verifier:** `verifier/` contains a self-contained browser application for signing and verifying coz messages, served locally via a Go HTTP server.

---

## Testing

CozJs uses [BrowserTestJS](https://github.com/Cyphrme/BrowserTestJS) for in-browser unit testing. Tests run in the browser because cryptographic operations depend on SubtleCrypto, which is only available in browser contexts.

- **Test runner:** BrowserTestJS (no Node.js test runner)
- **Run tests:** `cd verifier/browsertest && go run server.go` → navigate to `https://localhost:8082`
- **Test location:** `verifier/browsertest/`
- **Online tests:** [GitHub Pages](https://cyphrme.github.io/CozeJS/verifier/browsertest/browsertest.html)

---

## Security

This is a **cryptographic library**. Security considerations are paramount:

- **Constant time:** JavaScript provides no constant-time guarantees. This library is vulnerable to timing attacks. This is an inherent platform limitation pending [constant-time WASM](https://cseweb.ucsd.edu/~dstefan/pubs/renner:2018:ct-wasm.pdf).
- **Duplicate detection:** JavaScript objects silently accept duplicate keys (last-value-wins in ES6). `CheckDuplicate` must be called on serialized JSON for security-critical operations.
- **Signature canonicalization:** ECDSA signatures must be non-malleable. Signing functions must produce canonical (low-S) signatures.
- **Never commit private keys** or test keys with real value.
- **Coz spec compliance:** All cryptographic operations must match the behavior of the Go reference implementation. Cross-implementation test vectors in the Coz spec are authoritative.

---

## Configuration

- **No `.env` files.** No server-side configuration.
- **`$COZEJS` env var:** Must point to the repo root for `BUILD.sh` to function.
- **Go server:** The local dev server (`verifier/server.go`) serves on `https://localhost:8082` with a self-signed certificate.
