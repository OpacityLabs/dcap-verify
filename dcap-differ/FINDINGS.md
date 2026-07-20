# dcap-differ — differential findings vs Intel QVL

Oracle: Intel `libsgx_dcap_quoteverify.so.1.13.103.0` (QVL 1.13, host-side, no
enclave) via the pinned `intel-tee-quote-verification-rs = "0.3.0"`. Subject:
`dcap_verify::verify_remote_attestation`. Both verifiers are fed byte-identical
inputs; the quote's own MRENCLAVE is pinned so dcap-verify's measurement gate
never fires and cannot mask a core difference. Collateral is supplied explicitly
(no PCCS fetch).

> **Status (2026-07-09, post-hardening re-run).** The revised spec reclassified
> F3 and F5 from tolerated divergences to required Intel-matching behavior, and
> dcap-verify implements both (commit `a8060e2c`). All legs were
> re-run against the current crate; per-finding status lines below record what
> changed. Summary: **F5 is closed**; **F3 is closed at the parsed-value level
> but its sweep representatives still reproduce** (an encoding-level residue,
> see F3); **F1, F2, F4 are unchanged and ~~still open~~** for a policy decision
> (accepted as robustness — see the 2026-07-16 status below);
> the **TCB-level-selection coverage gap is closed** by unit tests in
> `dcap-verify/src/tcb.rs` (see that section). The corpus/results table
> reflects the re-run.

> **Status (2026-07-16).** F1, F2, the F3 encoding residue, and F4 are
> **accepted as robustness leniency** — one-line decision per finding below.
> Accepted ≠ forgotten: each stays recorded in `known-dangerous.json` and is
> replayed by CI, so any behavior change (tightening or widening) still
> surfaces as a deviation.

Marshaling was calibrated on `fixtures/prod-1`: QVL returns
`SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED` (exp_status 0), matching
dcap-verify's `ConfigurationAndSWHardeningNeeded` accept — so the marshaling is
trusted. (Aside: the installed QVL ignores the collateral version field and
accepts PEM or DER CRLs; all 8 calibration cells passed identically. 3.1/PEM was
chosen to match Intel QPL's real output.)

## Bottom line

**No authentication bypass was found.** dcap-verify never accepted a forged,
mismatched, or wrong-identity input. Every genuinely adversarial recombination —
wrong-FMSPC tcbInfo, sibling-CA CRL substitution, QE↔TCB slot swaps, QvE identity
as QE identity, TDX tcbInfo as SGX, and signer-pin chain substitution — was
correctly rejected on the dcap side.

Every divergence in the dangerous polarity (dcap accepts where QVL rejects) was
adversarially verified at the byte level and is **framing / parser leniency on
bytes outside all Intel-signed material**, not a trust bypass. In each case the
DER/tbs that dcap-verify actually authenticates is byte-identical to genuine
Intel data; the tolerated bytes are PEM whitespace, PEM-armor trailers, a
malformed-but-value-preserving outer `AlgorithmIdentifier` encoding, or a
redundant extra chain cert. (The one-second expiry boundary and value-level
outer-`AlgorithmIdentifier` mismatches were fixed in `a8060e2c` — see F3/F5.)

The remaining ones are still real, mechanically-reproducible divergences from
the reference implementation; each was **accepted as robustness** on
2026-07-16 (decision lines below) rather than tightened to match Intel. None
is a security regression, and the allowlist replay keeps each one as a
regression tripwire.

## Corpus and results

Re-run 2026-07-09 against the current crate (post-`a8060e2c`); the recombination
corpus was regenerated from Intel PCS (88 cases, all signed slots verified
byte-verbatim).

| Leg | Size | Result |
|---|---|---|
| `fixtures/` corpus | 17 cases | 12 agree (2 accept / 10 reject), 5 known-delta; 0 unexplained, 0 dangerous |
| Recombination corpus (genuine Intel artifacts, PCS v4) | 88 cases | 37 agree (23 accept / 14 reject), 42 known-delta, 8 unexplained-safe, **1 dangerous** (F4: `tE-tcbchain-root-twice`; the F5 case moved to known-delta) |
| Random-mutation sweep (seeds `0xDCAF00000011..13`) | 150,000 iters | 133,340 agree, 16,461 expiry-model, 42 debug-gate, 144 unexplained-safe, **13 dangerous** (8×F1, 1×F2, 4×F3 residue — each byte-verified), 0 standing-mismatch, 0 panic |

The sweep tallies are identical to the pre-`a8060e2c` run, and that is expected,
not a re-run artifact: value-level corruption of the outer
`AlgorithmIdentifier` was already rejected before the fix by the
ECDSA-with-SHA256 OID whitelist (so the fix's value-equality check adds no
sweep-visible rejections), and the random time mutation never lands on an exact
expiry instant (F5 is only reachable through the constructed
`tF-*` boundary cases in the recombination corpus, where the fix does show up).
The 13 dangerous cases are the same iterations as before; each was re-decoded
and confirmed to sit in the F1/F2/F3-residue framing classes.

> **2026-07-15.** The `fixtures/` oracle corpus has grown to 24 cases since the
> table above was recorded (still 0 dangerous: same-day re-run gives 18 agree
> (4 accept / 14 reject), 5 known-delta, 1 unexplained-safe — the new S4 case).
> The 10k-iteration seed-`0x…11` sweep tallies are unchanged, and a same-day
> regeneration of the recombination corpus reproduces the table's row exactly
> (37 agree, 42 known-delta, 8 safe, 1 dangerous = F4). A minimized 32-case
> subset of that corpus is now committed at `dcap-differ/corpus-committed/`,
> and the dangerous findings below are machine-readable in
> `known-dangerous.json` (see the CI note).

Reproduce any sweep case: `dcap-differ sweep --seed <hex> --iters 1 --only-iter <k>`.
The recombination corpus regenerates from Intel PCS via
`tools/build_recombination_corpus.py`. Both are deterministic (fixed SplitMix64
seed, printed at start).

The random sweep is a parser/polarity guard, not the high-signal leg: ~89% of
iterations mutate signed bytes and break a signature on **both** sides (trivial
agree-reject). The signal lives in the recombination corpus, which keeps Intel
signatures intact so QVL's verifier runs to completion and can genuinely
disagree.

---

## Findings for triage

### Dangerous-polarity divergences (dcap-verify accepts, QVL rejects)

All verified framing leniency; the "risk" column is trust risk, not the polarity
alarm. Any fix is a deliberate policy decision, not a quiet code change.

**F1 — PEM whitespace tolerance in the base64 body.** *Status 2026-07-09: OPEN,
unchanged — both representatives re-verified as still reproducing.*
*Decision 2026-07-16: **accepted as robustness** — the decoded DER is
byte-identical to the Intel-signed content, so strict base64 whitespace
policing adds no trust; kept in `known-dangerous.json` as a tripwire.*
dcap-verify's Rust PEM/base64 decoder skips non-alphabet bytes inside the base64
body (e.g. a line-break `0x0A` corrupted to VT `0x0B` or FF `0x0C`); OpenSSL/QVL
reject → `SGX_QL_PCK_CERT_CHAIN_ERROR`. The decoded DER is byte-identical, so
every Intel signature dcap checks still covers genuine content. Seen in the
quote-embedded PCK chain and in every collateral issuer chain.
Representative: sweep seed `0xDCAF00000011` iter 11818 (quote off 2119, `0x0A→0x0B`);
seed `0xDCAF00000011` iter 17387 (collateral, qe-identity chain, `\n→\f`).
Risk: none (decoded DER identical; forging any authenticated field needs
base64-alphabet changes that break a signature). Divergence class: robustness.

**F2 — Trailing / PEM-armor-trailer tolerance.** *Status 2026-07-09: OPEN,
unchanged — representative re-verified as still reproducing
(`trim_trailing_junk` in `dcap-verify/src/pki.rs` is deliberate).*
*Decision 2026-07-16: **accepted as robustness** — bytes outside the BEGIN/END
armor carry no authenticated payload, and real collateral plumbing emits
trailing NULs/whitespace (why `trim_trailing_junk` exists); kept allowlisted
as a tripwire.*
Bytes after `-----END …-----`, or trailing padding after the last cert, are
ignored by dcap-verify; QVL rejects. Also covers appended junk after the parsed
structure (the sweep never grows inputs, so pure trailing-append tolerance is
covered here only via in-place armor-trailer flips).
Representative: sweep seed `0xDCAF00000013` iter 23057 (collateral off 480, the
`\n` after root_ca_crl's END marker).
Risk: none (bytes outside BEGIN/END carry no authenticated payload).

**F3 — Unsigned outer `AlgorithmIdentifier` not enforced.** *Status 2026-07-09:
PARTIALLY FIXED in `a8060e2c`; both original representatives still reproduce.*
*Decision 2026-07-16: residue **accepted as robustness** — the tolerated byte
is unsigned and value-preserving, and closing it would need raw-DER
outer/inner comparison for no trust gain; the value-level equality check from
`a8060e2c` stays.*
The outer `signatureAlgorithm` of a cert or CRL (RFC 5280 §4.1.1.2, a redundant
restatement of the signed inner `tbsCertificate.signature`, **not** covered by
the signature) could be corrupted and dcap-verify still accepted; QVL rejects.
The fix narrows this to encoding-only corruption — see below. For a CRL the
outer-alg OID tag flip surfaces as `SGX_QL_CRL_UNSUPPORTED_FORMAT`.
Representatives: sweep seed `0xDCAF00000013` iter 36723 (qe-identity leaf cert,
DER off 572, past `tbsCertificate` end 570); seed `0xDCAF00000012` iter 35882
(root_ca_crl outer-alg OID tag `0x06→0x0E`, DER byte 209, outside `tbsCertList`
`[4,207)`).
*What the fix covers:* dcap-verify now requires the **parsed** outer
`AlgorithmIdentifier` (OID + parameters) to equal the signed inner copy for
every cert and CRL, with conformance tests (`dcap-verify/tests/conformance.rs`);
any value-level substitution or mismatch now rejects.
*What survives:* both representatives corrupt only a **tag byte** while leaving
the content bytes intact, and `x509-parser` 0.18.1 normalizes the malformed
encoding to the same parsed value (`OID 1.2.840.10045.4.3.2`), so the agreement
check cannot see the corruption — dcap accepts a DER whose outer-alg encoding
OpenSSL/QVL reject as malformed. Byte-level re-verified on the current crate
(2026-07-09); the 150k sweep re-run surfaced four such cases, covering three
tag-byte shapes, all normalized away by `x509-parser`: OID tag `0x06→0x0E`
(both original representatives), OID tag `0x06→0x16` (seed `0xDCAF00000013`
iter 21021), and the outer SEQUENCE tag `0x30→0x50` (seed `0xDCAF00000011`
iter 48160). In every case the mutated DER differs from genuine Intel data only
at the unsigned tag byte and the parsed values compare equal. Closing the
residue means comparing the outer/inner encodings at the raw-DER level (or
strict-parsing the outer field), not the parsed values — still a framing-only
decision, since the tolerated byte remains unsigned and value-preserving.
Note the sweep could never distinguish the fix: value-level outer-alg
corruption was already rejected pre-fix by the ECDSA-with-SHA256 OID whitelist,
so the fix's observable gain is rejecting a *valid-DER* outer alg that differs
from the inner copy (e.g. a different-but-well-formed algorithm restatement),
which random bitflips essentially never construct — that region is covered by
`tests/conformance.rs` instead.
Risk: none (field is unsigned and freely mutable by anyone; carries no
security-decision content). A strict verifier would additionally require the
outer copy to be byte-identical to the inner signed copy — Intel effectively
does (OpenSSL's strict DER parse), dcap now checks value equality only.

**F4 — Issuer-chain extra/duplicate-cert tolerance (recombination).** *Status
2026-07-09: OPEN, unchanged — `tE-tcbchain-root-twice` is the single remaining
dangerous-polarity case in the regenerated recombination corpus.*
*Decision 2026-07-16: **accepted as robustness** — anchoring at the pinned
root within the length cap is the security property; QVL's slot-specific
exact-count rule adds no trust; kept allowlisted as a tripwire.*
dcap-verify accepts a **genuine** `tcb_info_issuer_chain` of `[leaf, root, root]`
(a pure append of a duplicated, correctly-anchored Intel root); QVL rejects any
`tcb_info_issuer_chain` whose cert count ≠ 2 → `SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT`.
dcap accepts any chain ≤ its length cap whose terminal cert holds the pinned
Intel root key. Notably QVL's constraint is **slot-specific**: the identical
3-cert shape in `pck_crl_issuer_chain` is accepted by QVL (agree-accept).
Case: `corpus/tE-tcbchain-root-twice`.
Risk: none (leaf must still be CN `Intel SGX TCB Signing`, sign the tcbInfo, and
chain by real ECDSA signatures to the hardcoded pinned root). Divergence class:
QVL enforces an exact cert-count per collateral slot; dcap enforces only "anchors
at pinned root within length cap."

**F5 — Expiry boundary off-by-one (`>` vs `>=`) (recombination).** *Status
2026-07-09: FIXED in `a8060e2c`.*
Historical finding: at `current_time == pck_crl.nextUpdate`, dcap-verify treated
the CRL as still valid (strict `now > nextUpdate`) and accepted; QVL flags
`collateral_expiration_status = 1` at equality (its
`earliest_expiration_date <= check_date`). One-second leniency at the freshest
genuine CRL's expiry instant, applying to every collateral date.
dcap-verify now rejects at the exact expiry instant (`now >= nextUpdate` /
`notAfter`) for certificates, CRLs, tcbInfo and qeIdentity, matching QVL's
expiry boundary; the lower bounds stay inclusive-from-issue (see S2 for the
lower-bound delta, which QVL does not enforce at all). Covered by unit tests in
`dcap-verify/src/{lib,pki}.rs` and `tests/conformance.rs`.
Re-verified 2026-07-09: `corpus/tF-pckcrl-nextupdate-eq` (no bytes mutated;
only `current_time`) now classifies as the known expiry-model delta — dcap
hard-rejects with `cert-or-crl-time-invalid` where QVL reports `exp_status = 1`
with an otherwise-passing `qv_result` — instead of dangerous.

### Safe-polarity divergences (dcap-verify rejects, QVL accepts) — logged

Our added strictness; not defects, but record the intent so they are not
"fixed" into laxity later. These account for the 144 unexplained-safe sweep
records (plus the known-delta filters); the count is unchanged in the
2026-07-09 re-run.

- **S1 — dcap re-verifies every cert in every *provided* issuer chain**
  (signature over tbs, subject/issuer DN linkage, terminal-cert-holds-pinned-root,
  `ecdsa-with-SHA256` sig-alg OID, P-256 curve). QVL ignores provided issuer-chain
  copies it doesn't need and re-derives trust from its own anchor / the quote's
  PCK chain. This is the bulk of the safe-direction sweep records
  (`root-ca-untrusted`, `collateral-parse-error`).
- **S2 — dcap enforces a lower time bound** (`issueDate`/`notBefore`/`thisUpdate`
  in the future ⇒ reject); QVL enforces no lower bound (only expiry). Drives the
  `tF-*-issuedate-minus1` / `-eq` / `-plus1` boundary cases.
- **S3 — dcap binds the `pck_crl_issuer_chain` leaf subject to the quote's PCK
  issuer**; QVL does not bind that field to the CRL body, so it
  accepts a genuine processor CRL body carried under a platform-CA issuer chain
  (`corpus/tC-crl-processor-body-platform-chain`).
- **S4 — dcap rejects unconsumed bytes inside the quote's declared signature
  section** (added 2026-07-15). Bytes counted by `sig_len` but lying past the
  certification data were previously discarded without rejection; QVL accepts
  such a quote (verified: `fixtures/quote-sig-section-slack`, QVL returns
  `exp=0 CONFIG_AND_SW_HARDENING_NEEDED` where dcap rejects
  `quote-parse-error`). The slack is unauthenticated framing, so rejecting is
  the fail-closed direction; the fixture pins the behavior.
- **Known policy deltas (expected, filtered by the harness):** DEBUG-enclave
  rejection (QVL never inspects the app enclave's DEBUG attribute), the
  version/`tcbType` document-format gates, and the expiry-model delta (dcap
  `cert-or-crl-time-invalid` vs QVL `exp_status=1` with an otherwise-passing
  `qv_result`).

## Coverage gap (not a finding): TCB-level selection *order* — CLOSED

*Status 2026-07-09: the unit-test coverage this section called for exists in
`dcap-verify/src/tcb.rs` and passes — it landed with the revised-spec
conformance work (`740c9bb9`) and was overlooked when this document was first
written. No test CA turned out to be necessary: `platform_standing` is
exercised directly below the signature layer, so the tests construct arbitrary
(unsigned) `tcbLevels` arrays. `selection_is_document_order_first_not_maximum`
pins first-satisfied-in-document-order selection on a deliberately
**non-descending** array (the exact region this harness cannot reach) and
rejects a derived-maximum picker;
`first_satisfied_unaccepted_status_rejects_despite_later_uptodate`,
`first_satisfied_level_supplies_status_and_advisories`, and
`pcesvn_gates_level_satisfaction` pin the rest of the selection rule.*

Original gap, kept for the record: QVL 1.13 sorts `tcbLevels` **descending** by
the 16-component cpusvn vector then pceSvn (`std::set<TcbLevel,
std::greater<>>`) and returns the first satisfied level; dcap-verify iterates
in **document order**. For Intel's real collateral these coincide (PCS emits
descending order), which is why all genuine eval-19/20/21 and early/standard
tcbInfo documents agreed. The divergent case — a validly-signed document with
`tcbLevels` in non-descending order — cannot be built for this harness:
reordering breaks the Intel signature both verifiers check, and re-signing
needs a test CA that QVL will not accept against its pinned root. So the
black-box differential can never compare the two rules on a non-descending
document; the unit tests above pin dcap-verify's chosen behavior instead, and
the harness confirms the two rules agree on every genuine Intel document
reachable via PCS (eval numbers 19–21, early + standard tracks).

## Harness caveats (from the self-review; none invalidate the above)

- QVL `NotRun`/`Error` is counted as reject polarity — so "agree-reject" counts
  include comparisons where QVL failed before rendering a verdict. No record has
  wrong polarity; only the semantic strength of agree-reject is weaker than the
  label. dcap-accept-vs-QVL-not-run would surface as `DANGEROUS(qvl-not-run)`.
- The random sweep never *grows* inputs, so pure trailing-append tolerance is
  bounded, not exhaustively tested (F2 covers the in-place variant).
- The global panic hook stashes but does not print; a panic outside
  `run_dcap`'s `catch_unwind` (e.g. disk-full during a shard) would exit quietly.
  Shard JSONLs were checked internally consistent (line counts, case-dir counts,
  max iter).

## CI note

The tool is a standalone workspace-excluded binary (`exclude` in the root
`Cargo.toml`; own `[workspace]` stanza) and is not a dependency of any shipped
crate, so mobile/default builds never link the C library. It could run in the
non-SGX CI leg that already has `libsgx_dcap_quoteverify.so.1` installed: it needs
no enclave (host-side QVL, `qve_report_info = None`) and no network for the sweep
(`dcap-differ sweep`) or the fixtures (`dcap-differ fixtures`) legs. Only the
recombination-corpus *regeneration* needs Intel PCS; the generated corpus can be
committed and replayed offline.

Since 2026-07-15 the dangerous findings recorded above are machine-readable in
`dcap-differ/known-dangerous.json`, and `mise test-dcap-differ` (what CI runs)
passes that file to every leg via `--allow`: a recorded case that fires counts
as known-dangerous (CLEAN), one that stops firing counts as vanished (REVIEW),
and an unrecorded dangerous divergence stays REVIEW. The task requires every
leg to exit CLEAN — calibrate, the `fixtures/` oracle, the committed
recombination subset at `dcap-differ/corpus-committed/` (32 of the 88 cases,
covering every family and every recorded divergence class; refresh it by
regenerating the full corpus and re-copying the same case dirs), the full
corpus when locally present, a one-by-one replay of each recorded sweep
iteration, and the default 10k sweep — so any deviation fails CI. Fixing a
finding, or recording a new one, therefore means updating this file and
`known-dangerous.json` together.
