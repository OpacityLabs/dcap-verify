# DCAP verifier oracle fixtures

Ground-truth test vectors for `dcap-verify`.

The vectors are real quotes captured from live SGX enclaves, paired with
the FMSPC-`00a067110000` collateral (TCB info, QE identity, CRLs, issuer
chains) fetched from a PCCS. They are the regression oracle for
`dcap-verify` (`cargo test -p dcap-verify`). Two cases are captured bases; two
(`tcb-info-wrong-fmspc`, `prod-1-stale-qe-evaluation`) are genuine
Intel-signed splice cases built from live PCS by `tools/capture_wrong_fmspc.py`
and `tools/capture_stale_qe_evaluation.py`; the rest are deterministic
mutations regenerated from the bases by `tools/derive_fixtures.py` — treat all
of them as generated test data (edit the capture/derive step, not the files by
hand).

## Layout

Each case directory contains:

- `quote.bin` — SGX quote v3 bytes, passed to the verifier as-is
- `collateral.json` — collateral document, passed to the verifier as-is
- `meta.json`:
  - `current_time_unix` — the verification time to inject
  - `expected_mrenclave_hex` — the MRENCLAVE to pin
  - `verdict` — `accept` or `reject`
  - `category` — required rejection *class* (assert on your equivalent error
    variant; never on message text)
  - `tcb_standing` — on accept: `up-to-date`,
    `sw-hardening-needed { advisory_ids }`, or
    `configuration-and-sw-hardening-needed { advisory_ids }`
  - `min_tcb_evaluation_data_number` — optional; the TCB evaluation-round floor
    to pass to the verifier (absent = 0, no floor)
  - `notes` — what the case exercises

## Rejection categories

| category | meaning |
|---|---|
| `quote-parse-error` | quote bytes malformed, truncated, or unsupported version |
| `collateral-parse-error` | collateral document fails deserialization |
| `quote-signature-invalid` | attestation-key signature over the quote body fails |
| `qe-report-signature-invalid` | PCK-key signature over the QE report fails |
| `qe-binding-invalid` | QE report data does not bind the attestation key |
| `qe-vendor-invalid` | QE vendor id is not Intel's |
| `qe-identity-signature-invalid` | QE identity document signature fails |
| `qe-identity-stale` | QE identity past its next-update time or from a TCB evaluation round below the caller's minimum |
| `qe-identity-mismatch` | QE report fields do not match the QE identity document (exercised only by the synthetic e2e suite; no fixture uses it) |
| `tcb-info-signature-invalid` | TCB info document signature fails |
| `tcb-info-stale` | TCB info past its next-update time or from a TCB evaluation round below the caller's minimum |
| `cert-or-crl-time-invalid` | a certificate or CRL is outside its validity window |
| `crl-invalid` | CRL signature or content checks fail |
| `root-ca-untrusted` | chain does not terminate at the pinned Intel root |
| `tcb-level-unsupported` | platform TCB matches no acceptable level |
| `mrenclave-mismatch` | report MRENCLAVE differs from the pinned value |
| `debug-enclave-rejected` | report attributes carry the DEBUG flag |

## Coverage

Two captured bases drive the cases:

- `base-debug-enclave`: a DEBUG-mode SGX enclave (`sgx.debug = true`) —
  every stage before the debug gate passes; the debug attribute alone rejects.
  The debug-derived mutation cases build on it.
- `prod-1`: a production (non-debug) SGX enclave — the **accept** ground
  truth (`configuration-and-sw-hardening-needed` with advisory IDs), plus its
  mismatched-MRENCLAVE and stale-time variants.

Both bases are on FMSPC `00a067110000` / PCK Processor CA, so they share one
collateral document (the tcbInfo, QE identity, CRLs, and issuer chains are
Intel-signed per-FMSPC data, not per-quote).

## Regeneration

The corpus is reproducible.

1. **Capture a base** (needs a running SGX attestation endpoint + its PCCS):
   `python3 fixtures/tools/capture_base.py --out fixtures/<base> --attest
   <scheme>://<host>:9001 --pccs <scheme>://<host>:8081 --verdict <accept|reject>`.
   It fetches the quote, derives the FMSPC / PCK CA from it, pulls the four
   collateral pieces (`/sgx/certification/v4/{tcb?fmspc=…, qe/identity,
   pckcrl?ca=…, rootcacrl}`), and writes the case. The `tcbInfo`/`enclaveIdentity`
   response bodies are stored **verbatim** (their signatures cover the raw
   bytes); the issuer chains come from the response headers (URL-decoded); the
   CRLs are DER→PEM. For an `accept` base, fill `meta.json`'s `tcb_standing`
   from the standing the oracle test reports on its first run.
2. **Derive the mutations**: `python3 fixtures/tools/derive_fixtures.py`
   regenerates every derived case as a deterministic mutation of a base
   (quote-field flips, truncations, signed-body edits, or meta-only
   time/MRENCLAVE changes).
3. **Rebuild the splice cases** (needs network to Intel PCS):
   `python3 fixtures/tools/capture_wrong_fmspc.py` and
   `python3 fixtures/tools/capture_stale_qe_evaluation.py` splice genuine
   Intel-signed documents from other FMSPCs / older evaluation rounds into a
   base's collateral.

Each mutation is defined structurally (by quote-v3 field offset or an
unambiguous JSON edit). Extend
coverage either by adding a case to `derive_fixtures.py` or by dropping in a new
captured case directory (`quote.bin`, `collateral.json`, `meta.json`); the
`dcap-verify` oracle test discovers case directories automatically. Add the new
name to `REQUIRED_CASES` in `dcap-verify/tests/fixtures.rs` so an accidental
deletion of the case fails loud.
