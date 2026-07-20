---
name: dcap-verify-map
description: Map of the dcap-verify crate and its differential-testing harnesses (dcap-differ; signal-differ is planned, not yet in-tree) — verification pipeline, TCB policy, the fixture corpus and how to regenerate it, test/fuzz/mutation suites, and the stable consumer boundary. Load before changing verification logic, error categories, fixtures, or collateral handling, or when running/triaging the differ. Skip for code that merely calls the crate.
---

# dcap-verify Map

Verify against code before relying on specifics; this file describes
architecture, which changes slowly, but it can lag.

## Purpose

A from-scratch, MIT-licensed, pure-Rust verifier for **Intel SGX DCAP quote
v3** attestations against **Intel PCS v4 collateral**. No C dependencies, no
network, no async, no enclave: the
caller supplies quote bytes, a collateral document, the verification time, a
pinned MRENCLAVE, and a minimum TCB evaluation-data number; the crate returns
a verdict. It is designed to run inside a mobile TLS handshake.

The crate's canonical home is `github.com/OpacityLabs/dcap-verify`, which
also carries its full test apparatus: the ground-truth corpus at `fixtures/`
(repo root, resolved via `CARGO_MANIFEST_DIR/../fixtures` by the test suites
— including two `src/` unit tests — and via compile-time
`include_bytes!("../../../fixtures/...")` paths in the fuzz targets) and
`dcap-differ/`. Consumers take the crate as an ordinary Cargo dependency and
do not run its tests; the corpus, tests, fuzz, and differ exist in this repo
alone.

## Public API and the stable consumer boundary

Entry point (defined in `src/verify.rs` with the rest of the pipeline; `src/lib.rs` is the façade — re-exports, `TcbStanding`):

```rust
verify_remote_attestation(current_time, collateral, quote,
                          expected_mrenclave, min_tcb_evaluation_data_number)
    -> Result<(TcbStanding, SgxReportBody), VerifyError>
```

The surface that must stay stable across releases (each item's
guard test is noted; the call-shape/report-body lock is `tests/regression.rs`):

- `verify_remote_attestation` signature; `SgxQuote::read` (cursor-advancing —
  callers may have trailing data); `SgxCollateral` serde shape.
- `TcbStanding` — `UpToDate | SWHardeningNeeded | ConfigurationAndSWHardeningNeeded`
  (with advisory IDs). **Mechanism, not policy**: degraded-but-accepted
  standings are returned distinct so the caller decides. Its kebab-case serde
  tags are load-bearing (the fixture oracle in `tests/fixtures.rs` compares
  serialized JSON).
- `VerifyError { category, detail }` — `ErrorCategory::as_str()` slugs are
  stable and used verbatim in fixture `meta.json` (that oracle comparison is
  the pin). Categories are chosen at the rejection site; they are oracle
  classes, not a severity taxonomy.
- `peek_mrenclave` / `peek_report_data` — fixed-offset borrows from raw quote
  bytes **without verification**; offset/parser agreement is pinned by
  `tests/peek.rs`.
- `Signed<T>` keeps the raw JSON bytes of tcbInfo/enclaveIdentity — ECDSA
  signatures are verified over those verbatim bytes. **Never re-serialize
  signed collateral JSON anywhere** (crate, harnesses, or producers).
- `TcbPolicy` (`src/policy.rs`) + `verify_remote_attestation_with_policy` —
  stateless, caller-owned acceptance policy (floor + which degraded standings
  to accept; `UpToDate` always accepted; rejection category
  `tcb-standing-rejected`, pinned by `tests/policy.rs`). The crate carries the
  policy *mechanism* only — values stay caller-owned, no global state, no
  `Default`.

The min-evaluation-number constant is **caller-owned**: callers pin a named
constant and bump it per Intel TCB-recovery round; passing 0 disables the
floor. Typical consumers layer their own freshness/binding checks (e.g. an
EKM nonce or payload hash in the report data) on top of the verifier.

## Verification pipeline (order matters)

1. QE vendor-ID gate, then MRENCLAVE gate (cheapest checks first).
2. Document-format gates, fail-closed: collateral envelope v3, tcbInfo v3,
   enclaveIdentity v2, tcbType 0. Quote parsing itself gates version 3,
   ECDSA-P256 attestation key, cert-data type 5 (embedded PCK chain).
3. Four cert chains (three collateral issuer chains + the quote's PCK chain):
   pinned-Intel-root anchor check *first*, validity windows, ECDSA-P256
   algorithm enforcement including RFC 5280 outer-vs-inner agreement, CA/
   keyCertSign constraints, DN linkage, signatures. TCB-signing chains must
   have leaf CN exactly "Intel SGX TCB Signing" (chaining to root is not
   enough).
4. CRLs: root-CA CRL + PCK CRL, with **scope binding** — the PCK CRL's issuer
   must equal the quote's PCK leaf issuer (Intel runs sibling Processor and
   Platform CAs; a genuine-but-wrong-sibling CRL must reject; pinned by
   `tests/regression.rs`).
5. tcbInfo and QE identity: signature over raw bytes, validity window,
   evaluation-round floor (inclusive, applied to both documents), QE
   mrsigner/isvprodid/miscselect/attributes matching, QE isvsvn level must be
   UpToDate.
6. QE report signature (PCK leaf key), QE binding
   (SHA-256(attestation key ‖ auth data) == QE report_data), quote signature
   (attestation key over header+report).
7. DEBUG-enclave gate — deliberately **after** all signature checks (negative
   fixtures are debug captures that must reject for their *specific*
   mutation's category).
8. Platform TCB standing: FMSPC + PCE-ID from the PCK leaf's SGX extension
   must match tcbInfo, then level selection.

## TCB policy

`src/tcb.rs::platform_standing` iterates `tcbLevels` **in document order**
and takes the **first** level the platform satisfies. Do NOT reorder or pick
a maximum — levels are not totally ordered and any reordering can diverge
from Intel's QVL (unit-test-pinned). Accepted: UpToDate, SWHardeningNeeded,
ConfigurationAndSWHardeningNeeded (returned distinct). Everything else
(OutOfDate, ConfigurationNeeded, Revoked, no-match) rejects.

All expiry bounds are asymmetric on purpose: lower inclusive, upper
(`notAfter`, CRL/doc `nextUpdate`) **exclusive** — Intel QVL parity,
boundary-second tests pin both edges.

## Fixtures and tests

`fixtures/` (repo root) is the ground-truth oracle corpus, shared by the
crate tests, the fuzz targets, and dcap-differ. Read `fixtures/README.md`
before touching it. Key rules:

- Each case dir: `quote.bin` (committed binary — intentional),
  `collateral.json`, `meta.json` (injected verification time, expected
  MRENCLAVE, accept/reject verdict, rejection category slug, tcb standing).
  Time injection means fixtures never expire.
- A small set of **captured bases** (currently a DEBUG-enclave capture and a
  production-enclave accept case — `fixtures/README.md` owns the inventory);
  two genuine Intel-signed **splice cases** captured from live PCS
  (`fixtures/tools/capture_wrong_fmspc.py` /
  `capture_stale_qe_evaluation.py`); every other case is a deterministic
  mutation regenerated by `python3 fixtures/tools/derive_fixtures.py` (run
  from repo root). **Never hand-edit fixture files** — edit the derive script
  or recapture (base or splice; capture tools need network). New case dirs are
  auto-discovered by the oracle, which also pins the committed case names so
  a deleted case fails loud — add new cases to that inventory.
- Assertions are on error *category slugs*, never message text.

Contract anchors: `tests/fixtures.rs` (the oracle) and `tests/regression.rs`
(CRL scope substitution + the consumer-boundary lock). Further suites cover
requirements frozen fixtures can't stress — format-gate precedence,
signer-CN pinning, DER-surgery signature-algorithm mutations, window/floor
edges (`tests/conformance.rs`), truncation sweeps + proptest never-panics,
peek-offset pinning, and a cfg(test)-only synthetic PKI for the two rejection
sites real Intel-signed input can't reach (`src/synthetic_e2e.rs`, via a
thread-local test-only trust-anchor override in `src/pki.rs` — looks like a
backdoor but never compiles into dependents). The suite set grows; list
`tests/` rather than trusting this enumeration.

| action | command |
|---|---|
| unit + integration tests | `cargo test -p dcap-verify` |
| mutation testing | `cargo mutants -p dcap-verify` — policy: **0 missed**; a surviving mutant means a deletable security check |
| fuzz all targets | `mise fuzz-dcap` (`FUZZ_SECS` per target, `FUZZ_TARGETS` subset) |
| fuzz one target | `cd dcap-verify && cargo +nightly fuzz run <target>` |
| differential vs Intel QVL | `mise test-dcap-differ` |
| regenerate derived fixtures | `python3 fixtures/tools/derive_fixtures.py` |

Fuzzing: `fuzz/` is its own cargo workspace (excluded from the repo
workspace; needs nightly + cargo-fuzz). Targets include `quote_parse`,
`collateral_parse`, `verify_quote` (fuzzed quote, fixed prod collateral),
`verify_collateral` (inverse) — enumerate with `cargo +nightly fuzz list`.
Corpora accumulate locally under `fuzz/corpus/` (gitignored, not committed) —
exclude `corpus/`, `coverage/`, `artifacts/` when listing the crate.

## dcap-differ

Differential harness: byte-identical quote+collateral+time into
`dcap_verify::verify_remote_attestation` (under catch_unwind) and Intel QVL
(`tee_verify_quote` via the host `libsgx_dcap_quoteverify.so.1`), then
classify. Excluded from the repo workspace and never part of the crate as
consumed, because it links Intel's C library — which pure-Rust consumers
(e.g. mobile builds) must never link.

- **Exit-code contract** (durable, per binary invocation): 0 = CLEAN, 10 =
  REVIEW (an *unrecorded* dcap-accepts-where-QVL-rejects divergence, or a
  recorded one that vanished), 20 = FAIL (dcap panic or standing mismatch =
  real defect). The recorded dangerous findings are machine-readable in
  `dcap-differ/known-dangerous.json`, passed to `fixtures` and `sweep` via
  `--allow`: a matched dangerous record counts as known-dangerous (CLEAN),
  an in-scope entry that stops firing counts as vanished (REVIEW). `mise
  test-dcap-differ` passes the allowlist to every leg, additionally replays
  each recorded sweep iteration one-by-one, and requires every leg to exit
  CLEAN; any deviation exits 1. Fixing or adding a finding means updating
  FINDINGS.md and the allowlist together; read FINDINGS.md before "fixing"
  any REVIEW — safe-polarity findings are recorded there precisely so they
  aren't fixed into laxity.
- Four corpus legs: the shared `fixtures/` oracle; a committed, minimized
  **recombination subset** at `dcap-differ/corpus-committed/` (genuine
  Intel-signed artifacts in hostile arrangements — the high-signal leg,
  frozen so CI replays it offline); the full regenerable recombination
  corpus at `dcap-differ/corpus` (gitignored; build with
  `python3 dcap-differ/tools/build_recombination_corpus.py`, needs network to
  Intel PCS; the task runs it when locally present); and a deterministic
  random-mutation sweep (any finding reproduces exactly from seed +
  iteration). Refresh the committed subset by regenerating the full corpus
  and re-copying the same case dirs.
- Intentional design: the MRENCLAVE gate is neutralized (pinned from the
  quote itself) because QVL has no equivalent check; QVL NotRun/Error counts
  as reject polarity; known-delta filters cover deliberate policy differences
  (DEBUG rejection, format gates, hard expiry).
- Wired into CI in this repo (the differ job installs the host QVL library
  from Intel's apt repo); needs the host QVL library + libclang, Linux/x86_64.

## signal-differ

A second, lighter tripwire: replays libsignal's `rust/attest` DCAP test
fixtures through dcap-verify and diffs against a recorded expectations table.
Fixtures are fetched at first run (libsignal is AGPL — never commit them).
Not yet merged as of 2026-07 — search branches and PRs for `signal-differ`
before concluding it was removed. Its rows match
on verdict + a marker substring, so rewording an error message needs a marker
update, not a verdict change.

## Looks wrong but intentional

- DEBUG gate late in the pipeline (see above).
- Document-order-first TCB selection, not "best level".
- Exclusive upper time bounds everywhere (QVL parity).
- `trim_trailing_junk` PEM leniency in `src/pki.rs` — real collateral
  plumbing produces trailing NULs/whitespace; semantics are test-pinned and
  recorded as differ findings; neither widen nor drop it.
- `cfg(test)` trust-anchor override in `src/pki.rs` (synthetic e2e only).
- Peek helpers duplicate quote-offset knowledge next to the parser —
  single-crate ownership, drift-pinned by `tests/peek.rs`.
- The crate returns degraded TCB standings instead of rejecting them —
  policy belongs to the caller.

## Keeping this file current

Update only when the pipeline order/gates, TCB policy, public API, fixture
regeneration story, or differ contract changes — in the same PR. Don't add
volatile detail (fixture counts, finding IDs, dependency versions, the
current evaluation-number constant). This skill lives at the repo root
(`.agents/`) and is development apparatus, not part of the crate as consumed
by dependents.
