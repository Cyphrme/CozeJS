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
   - [ ] `test_unit.js`: All golden values from Go reference (`tmb`, `cad`, `sig`, `czd`)

2. **Phase 2: Behavioral Additions** — Implement timestamp validation, `RVK_MAX_SIZE`, and `SignPayRaw`.
   - [ ] `validateTimestamp()` — range check [0, 2^53-1], matches Go `Timestamp.Valid()`
   - [ ] `MaxSafeTimestamp` constant (`9007199254740991`)
   - [ ] `RVK_MAX_SIZE` — 2048 byte default, enforced on revoke payloads
   - [ ] `SignPayRaw` — sign without modifying `now` (new export)
   - [ ] New test cases for each feature

3. **Phase 3: Build + Documentation** — Rebuild bundles, update docs, document standard fields.
   - [ ] Rebuild `coze.min.js`, `coze_all.min.js`, `coze_standard.min.js` via `BUILD.sh`
   - [ ] Update `AGENTS.md` field references
   - [ ] Update `verifier/test_cozies.json5`
   - [ ] Document `msg`/`dig` standard fields per Coz README spec
   - [ ] Optional: README note on crypto lib choice (Ed25519ph/prehash context)

## Verification

- [ ] All 17 existing browser tests pass after Phase 1
- [ ] No references to old field names (`iat`, `kid`, `x` as Coz field, `d` as Coz field) remain in source
- [ ] No references to old naming (`coze` where `coz` is intended) remain in source
- [ ] Golden values (`tmb`, `cad`, `sig`, `czd`) match Go reference exactly
- [ ] New tests for timestamp validation, `RVK_MAX_SIZE`, `SignPayRaw` pass after Phase 2
- [ ] `BUILD.sh` completes without errors after Phase 3
- [ ] Verifier app functions correctly with rebuilt bundles

## Technical Debt

<!--
  Empty at plan creation. Populated during /core execution.
-->

| Item | Severity | Why Introduced | Follow-Up |
| :--- | :------- | :------------- | :-------- |

## Retrospective

<!--
  Filled in after execution is complete.
-->

### Process

- Did the plan hold up? Where did we diverge and why?
- Were the estimates/appetite realistic?
- Did CHALLENGE catch the risks that actually materialized?

### Outcomes

- What unexpected debt was introduced?
- What would we do differently next cycle?

### Pipeline Improvements

- Should any axiom/persona/workflow be updated based on this experience?

## References

- Sketch: [.sketches/2026-02-09-coz-1.0-migration.md](../../.sketches/2026-02-09-coz-1.0-migration.md)
- Go reference: [Cyphrme/Coz v1.0.0](https://github.com/Cyphrme/Coz)
- Issue tracker: [CozeX issue #2](https://github.com/Cyphrme/CozeX/issues/2)
