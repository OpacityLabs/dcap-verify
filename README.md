# dcap-verify

Pure-Rust verifier for Intel SGX DCAP quote v3 attestations against Intel PCS
v4 collateral. No C dependencies, no enclave, no network: the caller supplies
the quote bytes and the collateral documents, the crate returns a verdict. It
is designed to run inside a mobile TLS handshake.

| Path | What it is |
|---|---|
| `dcap-verify/` | the verifier crate — the only workspace member, and the unit consumers depend on |
| `fixtures/` | ground-truth oracle corpus shared by the tests, the fuzz targets, and the differ — see `fixtures/README.md` |
| `dcap-differ/` | differential-testing harness, dcap-verify vs Intel QVL — workspace-excluded because it links Intel's C library; see `dcap-differ/FINDINGS.md` |

## API

```rust
verify_remote_attestation(current_time, collateral, quote, expected_mrenclave,
                          min_tcb_evaluation_data_number)
    -> Result<(TcbStanding, SgxReportBody), VerifyError>
```

- Mechanism, not policy: accepted-but-degraded TCB statuses come back as
  distinct `TcbStanding` variants (with advisory IDs) for the caller to judge;
  everything worse is rejected outright.
- `min_tcb_evaluation_data_number` is the caller's freshness floor against
  TCB-recovery round downgrades (collateral from an older Intel evaluation
  round rejects even inside its `nextUpdate` window; `0` accepts any round).
  Callers should own a named constant and bump it per Intel evaluation round —
  Intel lists the current rounds at the PCS v4 `tcbevaluationdatanumbers`
  endpoint, and the `eval_standing` example prints the standing a given
  quote + collateral pair would get before you raise the floor. Only raise it
  once the collateral your deployment serves is at (or above) that round.
- Rejections are a `VerifyError { category, detail }`; `ErrorCategory` slugs
  are stable and machine-checkable (the fixture oracle asserts on them).
- `peek_mrenclave` / `peek_report_data` read fields from raw quote bytes
  without verifying.

## Trust model

The only trust anchor is Intel's SGX Root CA public key, hardcoded in
`dcap-verify/src/pki.rs` and compared unconditionally in every chain
validation. A `cfg(test)`-only, thread-local override exists for the synthetic
end-to-end suite (`src/synthetic_e2e.rs`); Rust never compiles a dependency's
`cfg(test)` code, so no shipped or downstream artifact contains that path.

## Testing

| action | command |
|---|---|
| unit + integration tests | `mise test` (plain `cargo test` works too) |
| lint / format | `mise lint` / `mise format` (`mise fix` applies both) |
| mutation testing | `mise mutants` |
| fuzz all targets | `mise fuzz-dcap` (`FUZZ_SECS` per target, default 60; `FUZZ_TARGETS` subset) |
| differential vs Intel QVL | `mise test-dcap-differ` |
| regenerate derived fixtures | `python3 fixtures/tools/derive_fixtures.py` |

- **Tests** replay the fixture corpus at `fixtures/` (two captured bases,
  deterministic mutations, and genuine Intel-signed PCS splices; every case's
  inputs and expected verdict live in its `meta.json` — see
  `fixtures/README.md`). The corpus lives only in this repo — it is the
  crate's test apparatus, not part of the crate as consumed by dependents.
- **Mutation testing** (`cargo install cargo-mutants`, ~10 minutes) must
  report **0 missed**: every surviving mutant is a code path no test pins,
  which for a verifier means a check that could be silently deleted. If a
  mutant survives after a change, add a test that kills it (see
  `dcap-verify/src/synthetic_e2e.rs` for the pattern used to pin call sites
  that genuine Intel-signed data cannot exercise) rather than accepting it.
  Timeout-class mutants (infinite loops) count as caught — `mise mutants`
  applies that policy to cargo-mutants' exit code (bare `cargo mutants` exits
  3 when timeouts occur).
- **Fuzzing** needs nightly + cargo-fuzz. Targets: `quote_parse`,
  `collateral_parse`, `verify_quote` (fuzzed quote against a fixed prod
  collateral embedded from `fixtures/` at compile time), `verify_collateral`
  (the inverse). Corpora accumulate locally under `dcap-verify/fuzz/corpus/`
  (gitignored).
- **The differ** feeds byte-identical quote+collateral+time to
  `verify_remote_attestation` and to Intel's QVL, then classifies every
  divergence. Linux x86_64 only; needs the host QVL library and libclang
  (no SGX hardware):

  ```sh
  sudo apt-get install libsgx-dcap-quote-verify-dev libsgx-headers libclang-dev clang
  ```

  (from Intel's apt repo, `https://download.01.org/intel-sgx/sgx_repo/ubuntu`
  — see `.github/workflows/ci.yml` for the full setup.)

  Verdict contract (per binary invocation): **CLEAN** (agreements, known
  policy deltas, dcap-stricter safe-direction, and allowlisted dangerous
  cases), **REVIEW** (an *unrecorded* dcap-accepts-where-QVL-rejects
  divergence, or a recorded one that vanished), **FAIL** (dcap-verify panic
  or standing mismatch — a real defect); exit codes 0/10/20. The recorded
  dangerous findings are machine-readable in
  `dcap-differ/known-dangerous.json`, which the `mise` task passes to every
  leg via `--allow` and additionally replays case-by-case: every leg must
  come back CLEAN, so the task exits 0 only when the recorded findings still
  reproduce and nothing unrecorded appears, and 1 on any deviation. Fixing or
  adding a finding means updating `dcap-differ/FINDINGS.md` and the allowlist
  together; read FINDINGS.md before "fixing" any recorded finding. Set
  `VERBOSE=1` for the full per-case tables.

  The high-signal recombination corpus (genuine Intel-signed artifacts in
  hostile arrangements) has a committed, minimized 32-case subset at
  `dcap-differ/corpus-committed/` that runs offline on every PR. The full
  88-case corpus is regenerable, not committed: build it with
  `python3 dcap-differ/tools/build_recombination_corpus.py` (network to Intel
  PCS); the differ picks it up automatically when present. Refresh the
  committed subset by regenerating and re-copying the same case dirs.

## Fixture tooling (`fixtures/tools/`)

- `derive_fixtures.py` — offline, deterministic regeneration of every mutation
  case from the two captured bases. Run after changing mutation definitions.
  **Never hand-edit fixture files.**
- `capture_base.py --out <dir> --attest <url> --pccs <url> --verdict <v>` —
  (re)capture a base fixture from a live SGX attestation endpoint + PCCS
  (network).
- `capture_wrong_fmspc.py` / `capture_stale_qe_evaluation.py` — build the
  genuine Intel-signed splice cases from live PCS (network); verification
  times are pinned at capture so committed fixtures never go stale.

## CI

Every PR runs: format check, clippy, tests, the differ (QVL installed from
Intel's apt repo), mutation testing (0-missed gate), and a fuzz smoke pass
(30s per target).

## Depending on the crate

`dcap-verify` is consumed as an ordinary Cargo dependency (e.g. a git
dependency on this repo). Everything else here — tests, `fixtures/`, the fuzz
targets, `dcap-differ/` — is the crate's development apparatus: it runs in
this repo's CI and is not part of the dependency. The crate's tests read
`../fixtures` at runtime, so run them from a checkout of this repo.

The public surface is treated as stable — changes to it are breaking. Its
guards: entry-point signature and report-body fields
(`dcap-verify/tests/regression.rs`), `TcbStanding` serde tags and
`ErrorCategory` slugs (the fixture oracle), peek helpers (`tests/peek.rs`).

## License

MIT (`LICENSE-MIT`).
