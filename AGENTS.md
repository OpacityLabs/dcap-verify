# Agent Instructions

Architecture map: `.agents/skills/dcap-verify-map/SKILL.md` — load it before
changing verification logic, error categories, fixtures, collateral handling,
or the differ.

## Commands

- `mise test` — unit + integration (plain `cargo test` works too; no harness).
  Fixture data resolves to `../fixtures` relative to the dcap-verify crate.
- `mise test-dcap-differ` — differential vs Intel QVL (needs the host QVL
  library + libclang). Recorded dangerous cases live in
  `dcap-differ/known-dangerous.json`, passed to every leg via `--allow`: a
  recorded case that fires is fine (known-dangerous), one that stops firing
  is a deviation (vanished), and anything unrecorded stays dangerous. Every
  leg — including the committed recombination subset at
  `dcap-differ/corpus-committed/` and a replay of the recorded sweep
  iterations — must come back CLEAN. Exit 0 = all legs CLEAN; exit 1 =
  deviation — triage against `dcap-differ/FINDINGS.md` (update it and the
  allowlist together), and read it before "fixing" any recorded finding.
- `mise mutants` — mutation testing; the policy is **0 missed**: a surviving
  mutant is a security check that can be deleted without a test failing.
  Timeout-class mutants count as caught.
- `mise fuzz-dcap` — fuzz targets (nightly + cargo-fuzz).
- After changes run `mise fix` (clippy --fix + fmt). CI enforces
  `cargo fmt --check`, clippy `-D warnings`, tests, differ, mutants, and a
  fuzz smoke.

## Conventions

- Downstream projects consume the crate as an ordinary Cargo dependency;
  tests, `fixtures/`, fuzz, and `dcap-differ/` are development apparatus —
  consumers do not run this crate's tests, so full coverage runs in this
  repo's CI only.
- The public API is a stability boundary — treat changes as breaking. Its
  guards: entry-point signature and report-body fields
  (`dcap-verify/tests/regression.rs`), `TcbStanding` serde tags and
  `ErrorCategory` slugs (the fixture oracle, `tests/fixtures.rs`), peek
  helpers (`tests/peek.rs`), and the collateral-selection helper
  (`pck_collateral_params` / `PckCa` wire strings — surface lock in
  `tests/regression.rs`, quote-vs-collateral cross-check in `tests/peek.rs`).
- **Never hand-edit fixture files** — edit `fixtures/tools/derive_fixtures.py`
  and regenerate, or recapture (base or splice; capture tools need network).
  Fixture assertions use error-category slugs, never message text. See
  `fixtures/README.md`.
- Never re-serialize signed collateral JSON (tcbInfo / enclaveIdentity) —
  signatures are verified over the raw bytes.
- If your change moves architecture (pipeline gates, TCB policy, public API,
  fixture/differ story), update the skill file in the same PR. No volatile
  detail there (counts, versions, finding IDs).
