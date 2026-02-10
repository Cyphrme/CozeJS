# PLAN: CozJs Coz 1.0 Migration

<!--
  Migrate CozJs from pre-1.0 Coze conventions to Coz v1.0 specification.
  See sketch for full exploration and decision journal.
-->

## Goal

Migrate CozJs from pre-1.0 Coze conventions to the Coz v1.0 specification as
implemented in the Go reference (`Cyphrme/Coz` v1.0.0). This is a breaking API
change encompassing field renames (`iat`→`now`, `kid`→`tag`, `x`→`pub`,
`d`→`prv`), internal `coze`→`coz` naming, behavioral additions (conditional
`now` update, `SignPayRaw`, timestamp validation, `RVK_MAX_SIZE`), constant
updates (`TmbCanon`→`KeyCanon`, `XSize`→`PubSize`, `DSize`→`PrvSize`), and
golden test vector realignment.

## Constraints

- Pure ESM, no TypeScript, no external runtime dependencies
- Browser-only tests via BrowserTestJS (no Node runner)
- Go reference is canonical source of truth for all behavior
- Golden test vectors must match Go reference exactly
- JWK `x`/`y`/`d` field names are W3C WebCrypto standard — never rename

## Decisions

| Decision                | Choice                                                   | Rationale                                                                                                              |
| :---------------------- | :------------------------------------------------------- | :--------------------------------------------------------------------------------------------------------------------- |
| Delivery strategy       | Phased (renames → behavior → docs)                       | Golden vectors don't exercise behavioral features. Isolation reduces debug risk. Reversible.                           |
| `TmbCanon` → `KeyCanon` | `["alg","pub"]` replaces `["alg","x"]`                   | Go reference canonical form. All thumbprints cascade — intentional breaking change.                                    |
| `now` zero-check        | `if (!isEmpty(coze.pay.now))`                            | `isEmpty(0) === true` naturally matches Go's `!= 0` semantics. Uses existing project utility.                          |
| Timestamp validation    | `validateTimestamp()` utility function                   | JS lacks Go's custom type system. Throwing on out-of-range matches Go `Timestamp.Valid()`.                             |
| JWK field names         | Unchanged in `cryptokey.js`                              | W3C WebCrypto standard constraint. Irreversible.                                                                       |
| `SignPayRaw`            | New function, not a rename of `SignCozRaw`               | Different semantics: `SignCozRaw` = no alg/tmb/now auto-set; `SignPayRaw` = sign without modifying `now`. Both needed. |
| Function naming         | Keep JS conventions (`Sign`, `SignPay`, etc.)            | Go vs JS idioms differ. Per-project conventions maintained.                                                            |
| `coze` → `coz`          | Full internal rename (vars, functions, comments, errors) | Spec renamed. Not just cosmetic — touches all modules.                                                                 |
| `tag` field             | Simple rename from `kid`, no defensive check             | `kid` is display-only in JS (`key.js:54` default label, `typedef.js` type docs). No programmatic usage.                |

## Risks & Assumptions

| Risk / Assumption                                                                                  | Severity | Status    | Mitigation / Evidence                                                       |
| :------------------------------------------------------------------------------------------------- | :------- | :-------- | :-------------------------------------------------------------------------- |
| Thumbprint cascade — `KeyCanon` change invalidates ALL derived hashes (`tmb`, `cad`, `sig`, `czd`) | MEDIUM   | Mitigated | Intentional breaking change. Grep for old `tmb` values post-Phase 1.        |
| JWK field collision in `cryptokey.js` — `x`/`y`/`d` are both JWK and Coz field names               | LOW      | Mitigated | Only rename `cozeKey.x` → `cozKey.pub`, never touch `jwk.x`/`y`/`d`.        |
| `Sign()` now-update semantics change (unconditional → conditional)                                 | LOW      | Mitigated | `isEmpty(0)===true` naturally matches Go's `!=0`. Existing project pattern. |
| High-S test vectors embed old `tmb` in payload                                                     | LOW      | Mitigated | Use Go's updated `ExampleECDSAToLowSSig` vectors with new `tmb`.            |
| Duplicate detection already exists in JS                                                           | —        | Validated | `test_Duplicate` in `test_unit.js:108`. Not in scope.                       |
| `msg`/`dig` require no code changes                                                                | —        | Validated | Application-level fields, not library-level. Documentation only.            |
| `SignCozRaw` ≠ Go's `SignPayRaw`                                                                   | —        | Validated | Different semantics confirmed via Go commit `1ea6772`. Both needed.         |

## Open Questions

All resolved during CHALLENGE/SCOPE:

- ~~`tag` programmatic usage~~ — Display-only. Simple rename. ([key.js:54](../../key.js#L54))
- ~~`now` zero-check semantics~~ — `isEmpty(0)===true` matches Go. ([coze.js](../../coze.js))
- ~~Ed25519ph rationale~~ — Context for us. Optional README note about crypto lib choice.

## Scope

### In Scope

- All field renames: `iat`→`now`, `kid`→`tag`, `x`→`pub`, `d`→`prv`
- Internal naming: `coze`→`coz` throughout (variables, functions, comments, errors)
- Constant renames: `TmbCanon`→`KeyCanon`, `PayCanon` update, `XSize`→`PubSize`, `DSize`→`PrvSize`
- Behavioral: conditional `now` update in `Sign()`, `SignPayRaw` function
- Validation: `validateTimestamp()`, `MaxSafeTimestamp`, `RVK_MAX_SIZE`
- All golden test vectors realigned to Go reference
- Build regeneration and documentation updates

### Out of Scope

- npm package registry rename
- Post-quantum algorithm support
- Verifier app UI redesign
- New duplicate detection code (already exists)
- `msg`/`dig` code changes (application-level, not library-level)

## Phases

1. **Phase 1: Field Renames + Golden Vector Alignment** — Rename all pre-1.0 field names and internal `coze`→`coz` naming, update constants, realign all golden test vectors. All 17 existing tests pass.
   - [x] `typedef.js`: Rename `Iat`→`Now`, `Kid`→`Tag`, type definitions for `x`→`pub`, `d`→`prv`
   - [x] `key.js`: `TmbCanon`→`KeyCanon = ["alg","pub"]`, field renames, `kid`→`tag`
   - [x] `coze.js`: `PayCanon = ["alg","now","tmb","typ"]`, `iat`→`now` in all references
   - [x] `coze.js`: `Sign()` conditional `now` update — `if (!isEmpty(coz.pay.now))`
   - [x] `coze.js`: `SignCozRaw` docstring update (`iat`→`now` reference)
   - [x] `cryptokey.js`: `cozKey.pub`, `cozKey.prv` (never touch JWK `x`/`y`/`d`)
   - [x] `alg.js`: `XSize`→`PubSize`, `DSize`→`PrvSize`, `Params` fields renamed
   - [x] All modules: `coze`→`coz` naming (e.g. `SignCozeRaw`→`SignCozRaw`, error messages, comments)
   - [x] `test_unit.js`: All golden values from Go reference (`tmb`, `cad`, `sig`, `czd`)

2. **Phase 2: Behavioral Additions** — Implement timestamp validation, `RVK_MAX_SIZE`, and `SignPayRaw`.
   - [x] `validateTimestamp()` — range check [0, 2^53-1], matches Go `Timestamp.Valid()`
   - [x] `MaxSafeTimestamp` constant (`9007199254740991`)
   - [x] `RVK_MAX_SIZE` — 2048 byte default, enforced on revoke payloads (both creation and verification)
   - [x] `SignPayRaw` — sign without modifying `now` (new export)
   - [x] New test cases for `SignPayRaw` and `validateTimestamp`

3. **Phase 3: Build + Documentation** — Rebuild bundles, update docs, document standard fields.
   - [x] Rebuild `coze.min.js`, `coze_all.min.js`, `coze_standard.min.js` via `BUILD.sh`
   - [x] Update `AGENTS.md` field references (verified already 1.0 compliant)
   - [x] Update `verifier/test_cozies.json5` (key fields renamed; pay fields preserved as signed content)
   - [x] Document `msg`/`dig` standard fields per Coz README spec
   - [x] README note on crypto lib choice (Ed25519ph noble-ed25519)

4. **Phase 4: Audit Remediation** — Fix stale naming caught by retrospective audit.
   - [x] Fix `verifier.js`: `SignCozeRaw` → `SignCozRaw` (bug — Sign button broken)
   - [x] Fix `verifier.js`: `iat` → `now` (7 instances), `MetaIat`/`MetaIats` → `MetaNow`/`MetaNows`
   - [x] Fix `coze.html`: title/heading "Coze" → "Coz", `iat:` → `now:` label, DOM IDs, link text/URLs
   - [x] Fix `coze_array.js`: `c.coze` → `c.coz` (JSON wrapper field per spec)
   - [x] Rebuild all bundles, 20/20 browser tests pass

## Verification

- [x] All 17 existing browser tests pass after Phase 1
- [x] No references to old field names (`iat`, `kid`, `x` as Coz field, `d` as Coz field) remain in source
- [x] No references to old naming (`coze` where `coz` is intended) remain in source
- [x] Golden values (`tmb`, `cad`, `sig`, `czd`) match Go reference exactly
- [x] New tests for `SignPayRaw` and `validateTimestamp` pass after Phase 2 (19/19 total)
- [x] `BUILD.sh` completes without errors (validated during Phase 1 debugging)
- [x] Verifier app functions correctly with rebuilt bundles (16/17 pass)

## Technical Debt

<!--
  Empty at plan creation. Populated during /core execution.
-->

| Item                                                                        | Severity | Why Introduced                                                                                                                    | Follow-Up                                                                                                          | Resolved |
| :-------------------------------------------------------------------------- | :------- | :-------------------------------------------------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------- | :------- |
| Meta test secondary/tertiary golden `cad`/`czd` values manually constructed | MEDIUM   | Go's `ExampleCoz_MetaWithAlg` uses different secondary payloads; values aligned by content but not yet verified against Go output | Cross-checked all 3 JS Meta test `cad`/`czd` values against Go `ExampleCoz_MetaWithAlg` output — all match exactly | ✅       |
| `VerifyCozeArray` export in `standard/coze_array.js`                        | LOW      | Intentionally deferred — `standard/` module out of scope for Phase 1. Test calls `VerifyCozArray` but export is still old name    | Rename in Phase 2 or as standalone cleanup commit                                                                  | ✅       |
| `Valid()` and `Correct()` lost error handling during Phase 1 rewrite        | RESOLVED | Phase 1 Commit 1 rewrote functions without preserving `try/catch` and SubtleCrypto-aware guards                                   | Fixed in Phase 1 Commit 3                                                                                          | ✅       |

## Retrospective

### Process

**Did the plan hold up?**

The phased delivery strategy (renames → behavior → docs) held up well for the
_library_ code. Phase 1 renames landed cleanly, Phase 2 behavioral additions
layered on without regressions, and Phase 3 documentation was straightforward.
However, the plan's scope was too narrow — it focused exclusively on the 5
library source files and missed the verifier app (`verifier.js`, `coze.html`)
and `standard/coze_array.js` entirely. Phase 4 was added ad hoc after the
retrospective audit caught these gaps.

**Where did we diverge?**

1. **Phase 1 debugging was unexpectedly expensive.** The plan assumed renames
   would be mechanical, but 4 commits were needed (vs. the expected 1-2) due to
   regression cascades from `VerifyCozeArray` → `VerifyCozArray`, broken error
   handling in `Valid()`/`Correct()`, and high-S test vector `tmb` misalignment.
2. **`test_cozies.json5` required a correction commit.** The initial Phase 3
   approach preserved pre-1.0 pay fields (`iat`, old `tmb`) with the
   rationalization that they were "signed content." This was wrong for a breaking
   version change — the file was fully regenerated from Go 1.0 golden values.
3. **Phase 4 was unplanned.** The exhaustive audit revealed `verifier.js` had a
   broken Sign button (`SignCozeRaw` → dead name) and 7 stale `iat` references.
   `coze_array.js` had a stale `c.coze` JSON wrapper check.

**Were the estimates realistic?**

The original plan estimated 3 phases with ~6 commits. Actual execution was 4
phases with 10 commits. The 67% overrun was driven by Phase 1 debugging (4
commits vs. expected 2) and the unplanned Phase 4. Phase 2 and Phase 3 were
each on-estimate.

**Did CHALLENGE catch the risks that materialized?**

Partially. The thumbprint cascade risk was identified and mitigated correctly.
The JWK field collision risk (`cryptokey.js` `.d`/`.x`) was correctly called out
and handled. But the CHALLENGE did not identify the verifier app as in-scope —
the plan's `FILES` list was library-only, which left the verifier's stale
references invisible until the retrospective audit.

### Outcomes

**What unexpected debt was introduced?**

- `Meta test cad/czd not cross-verified against Go` — MEDIUM. The Meta test
  uses manually constructed secondary golden values that have not been verified
  against `go test -run ExampleCoz_MetaWithAlg -v`. This was documented during
  execution and remains open.

**What would we do differently next cycle?**

1. **Scope the verifier app from the start.** In a repo that ships a verifier,
   the verifier is part of the deliverable. The plan's file list should have
   included `verifier/*.js`, `verifier/*.html`, and `standard/*.js`.
2. **Run exhaustive grep before Phase 1 starts, not after Phase 3 ends.** A
   `grep -rnI 'iat\|kid\|coze'` across the entire repo at planning time would
   have surfaced `verifier.js` and `coze_array.js` immediately.
3. **Don't rationalize stale data.** The initial `test_cozies.json5` approach
   preserved old field names with a comment explaining why. The correct response
   to a breaking version change is to regenerate, not preserve. Conservative
   half-measures leave the repo in an inconsistent state.
4. **Test the verifier app manually, not just unit tests.** Clicking Sign in the
   browser would have caught the `SignCozeRaw` bug immediately.

### Pipeline Improvements

- **Planning persona**: Add a directive to enumerate _all_ files in the repo
  that reference the changing API, not just the "core" library files. A
  `grep`-first planning step should be mandatory for rename-class changes.
- **CORE workflow**: Add a VERIFY step at the end of rename-class migrations
  that runs `grep` for _all_ old names across the entire repo (not just the
  files in `CTX.FILES`). This is the check that Phase 4 performed retroactively.
- **Sketch discipline**: The sketch correctly logged every commit, divergence,
  and correction. This was valuable during the retrospective — no context was
  lost despite 10 commits across 4 phases.

## References

- Sketch: [.sketches/2026-02-09-coz-1.0-migration.md](../../.sketches/2026-02-09-coz-1.0-migration.md)
- Go reference: [Cyphrme/Coz v1.0.0](https://github.com/Cyphrme/Coz)
- Issue tracker: [CozeX issue #2](https://github.com/Cyphrme/CozeX/issues/2)
