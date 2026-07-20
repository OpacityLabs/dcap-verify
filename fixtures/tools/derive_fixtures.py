#!/usr/bin/env python3
"""
Regenerate the derived dcap-verify oracle fixtures from the two captured bases.

The corpus has two *captured* base cases — `base-debug-enclave` (a DEBUG-mode
enclave) and `prod-1` (the production non-debug enclave) — each a real quote plus
the FMSPC-00a067110000 collateral fetched from a PCCS. Every other case
is a deterministic mutation of one of those two, produced here so the whole
corpus is reproducible (see fixtures/README.md). Bases are NOT
touched by this script.

Run from the repo root:  python3 fixtures/tools/derive_fixtures.py

Each mutation is defined structurally (by quote-v3 field offset or by an
unambiguous JSON edit).
"""
import json, os, re, struct, sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FX = os.path.join(ROOT, "fixtures")

# Quote v3 byte offsets (header 48B, then the 384B report body, then signature).
OFF_VERSION = 0            # u16 LE
OFF_ATT_KEY_TYPE = 2       # u16 LE
OFF_QE_VENDOR_ID = 12      # 16 B
OFF_ATTR_FLAGS = 96        # report body attributes.flags (DEBUG = bit 1)
OFF_ISV_SIG = 436          # ECDSA sig over header+report (64 B)
OFF_ATTEST_PUBKEY = 500    # attestation public key (64 B)
OFF_QE_REPORT_SIG = 948    # PCK-key sig over the QE report (64 B)
OFF_QE_AUTH_DATA = 1014    # 32 B (the u16 length field at offset 1012 is 32 in both bases)
OFF_CERT_DATA_TYPE = 1046  # u16 LE
OFF_SIG_LEN = 432          # u32 LE, declared length of the signature section

# Verification times relative to the captured collateral (issued 2026-07-08,
# certs valid 2018-05..2032-05). In-window value reaches each mutation's own
# gate; the far bounds fall outside every certificate's validity window.
BASE_TIME = 1783549518     # ~2026-07-08, inside the collateral/cert window
FAR_FUTURE = 2355682800    # ~2044, past the TCB-signing cert's notAfter
FAR_PAST = 1000000000      # 2001, before any cert's notBefore
WRONG_MRENCLAVE = "aa" * 32


def load_base(name):
    d = os.path.join(FX, name)
    quote = open(os.path.join(d, "quote.bin"), "rb").read()
    collateral = open(os.path.join(d, "collateral.json")).read()
    mrenclave = quote[112:144].hex()
    return quote, collateral, mrenclave


def flip(buf, off):
    b = bytearray(buf)
    b[off] ^= 0x01
    return bytes(b)


def clear_debug_bit(buf):
    b = bytearray(buf)
    b[OFF_ATTR_FLAGS] &= ~0x02  # strip DEBUG without re-signing
    return bytes(b)


def set_u16(buf, off, v):
    b = bytearray(buf)
    struct.pack_into("<H", b, off, v)
    return bytes(b)


def add_sig_slack(buf, n):
    """Grow sig_len by n and insert n zero bytes after the certification data,
    inside the declared signature section but past every parsed field."""
    sig_len = struct.unpack_from("<I", buf, OFF_SIG_LEN)[0]
    end = OFF_SIG_LEN + 4 + sig_len
    b = bytearray(buf)
    struct.pack_into("<I", b, OFF_SIG_LEN, sig_len + n)
    b[end:end] = b"\x00" * n
    return bytes(b)


def bump_issue_date(collateral_text, which):
    """Advance the issueDate year by one inside one signed document, breaking its
    signature while leaving the JSON well-formed. `which` in {tcb, qe}; the
    tcb_info object precedes qe_identity in the collateral, so scope by key."""
    i_tcb = collateral_text.index('"tcb_info":')
    i_qe = collateral_text.index('"qe_identity":')
    lo, hi = (i_tcb, i_qe) if which == "tcb" else (i_qe, len(collateral_text))
    seg = collateral_text[lo:hi]
    m = re.search(r'"issueDate":"(\d{4})(-\d\d-\d\dT\d\d:\d\d:\d\dZ)"', seg)
    if not m:
        raise SystemExit(f"issueDate not found for {which}")
    seg = seg[: m.start()] + f'"issueDate":"{int(m.group(1))+1}{m.group(2)}"' + seg[m.end():]
    return collateral_text[:lo] + seg + collateral_text[hi:]


def write_case(name, quote, collateral, meta):
    d = os.path.join(FX, name)
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "quote.bin"), "wb").write(quote)
    open(os.path.join(d, "collateral.json"), "w").write(collateral)
    meta = {"case": name, **meta}
    with open(os.path.join(d, "meta.json"), "w") as f:
        json.dump(meta, f, indent=2)
        f.write("\n")


def rej(cat, notes, t=BASE_TIME, mre=None, min_eval=0):
    meta = {"current_time_unix": t, "expected_mrenclave_hex": mre,
            "verdict": "reject", "category": cat, "notes": notes}
    if min_eval:
        meta["min_tcb_evaluation_data_number"] = min_eval
    return meta


def main():
    dq, dc, dmre = load_base("base-debug-enclave")
    pq, pc, pmre = load_base("prod-1")
    prod_round = json.loads(pc)["tcb_info"]["tcbInfo"]["tcbEvaluationDataNumber"]

    # (name, quote, collateral, meta) — all derived from a captured base.
    cases = [
        # --- quote mutations on the debug base ---
        ("qe-vendor-id-flip", flip(dq, OFF_QE_VENDOR_ID), dc,
         rej("qe-vendor-invalid", "QE vendor id corrupted; no longer Intel's.", mre=dmre)),
        ("isv-signature-bitflip", flip(dq, OFF_ISV_SIG), dc,
         rej("quote-signature-invalid", "One bit flipped in the ISV quote signature.", mre=dmre)),
        ("attest-pubkey-bitflip", flip(dq, OFF_ATTEST_PUBKEY), dc,
         rej("qe-binding-invalid", "One bit flipped in the attestation public key; breaks the QE-report binding.", mre=dmre)),
        ("qe-report-signature-bitflip", flip(dq, OFF_QE_REPORT_SIG), dc,
         rej("qe-report-signature-invalid", "One bit flipped in the QE report signature.", mre=dmre)),
        ("qe-auth-data-bitflip", flip(dq, OFF_QE_AUTH_DATA), dc,
         rej("qe-binding-invalid", "One bit flipped in the QE authentication data; report_data no longer equals SHA256(attest_pubkey || auth_data).", mre=dmre)),
        ("attributes-debug-bit-cleared", clear_debug_bit(dq), dc,
         rej("quote-signature-invalid", "DEBUG bit cleared in the report body without re-signing: stripping the flag must break the signature, not produce an accept.", mre=dmre)),
        ("quote-version-4", set_u16(dq, OFF_VERSION, 4), dc,
         rej("quote-parse-error", "Header version field set to 4; only v3 is in scope.", mre=dmre)),
        ("quote-att-key-type-1", set_u16(dq, OFF_ATT_KEY_TYPE, 1), dc,
         rej("quote-parse-error", "Attestation key type set to 1; only ECDSA-P256 (type 2) is in scope.", mre=dmre)),
        ("quote-cert-data-type-1", set_u16(dq, OFF_CERT_DATA_TYPE, 1), dc,
         rej("quote-parse-error", "Certification data type set to 1; only an embedded PCK chain (type 5) is in scope.", mre=dmre)),
        ("quote-sig-section-slack", add_sig_slack(dq, 4), dc,
         rej("quote-parse-error", "sig_len grown by 4 zero bytes after the certification data; unconsumed signature-section bytes must reject, not be silently discarded.", mre=dmre)),
        ("quote-truncated", dq[:100], dc,
         rej("quote-parse-error", "Quote cut to 100 bytes.", mre=dmre)),
        # --- collateral mutations on the debug base ---
        ("tcb-info-tampered", dq, bump_issue_date(dc, "tcb"),
         rej("tcb-info-signature-invalid", "issueDate changed inside the signed tcbInfo body; signature no longer covers the content.", mre=dmre)),
        ("qe-identity-tampered", dq, bump_issue_date(dc, "qe"),
         rej("qe-identity-signature-invalid", "issueDate changed inside the signed enclaveIdentity body.", mre=dmre)),
        ("collateral-truncated", dq, dc[: len(dc) // 2],
         rej("collateral-parse-error", "Collateral JSON cut in half.", mre=dmre)),
        # --- meta-only cases on the debug base ---
        ("wrong-mrenclave", dq, dc,
         rej("mrenclave-mismatch", "Caller pins an MRENCLAVE that does not match the quote.", mre=WRONG_MRENCLAVE)),
        ("time-far-future", dq, dc,
         rej("cert-or-crl-time-invalid", "Verification time ~20 years after capture; certs stale.", t=FAR_FUTURE, mre=dmre)),
        ("time-far-past", dq, dc,
         rej("cert-or-crl-time-invalid", "Verification time in 2001, before any cert in the chain is valid.", t=FAR_PAST, mre=dmre)),
        # --- meta-only cases on the prod base ---
        ("prod-1-wrong-mrenclave", pq, pc,
         rej("mrenclave-mismatch", "Captured quote with a mismatched pinned MRENCLAVE.", mre=WRONG_MRENCLAVE)),
        ("prod-1-time-far-future", pq, pc,
         rej("cert-or-crl-time-invalid", "Captured quote verified ~20 years later; certs stale.", t=FAR_FUTURE, mre=pmre)),
        ("prod-1-stale-tcb-evaluation", pq, pc,
         rej("tcb-info-stale", f"Genuine round-{prod_round} collateral verified with a caller floor of {prod_round + 1}: an old-but-unexpired TCB evaluation round must reject as stale.", mre=pmre, min_eval=prod_round + 1)),
    ]
    for name, q, c, meta in cases:
        write_case(name, q, c, meta)
    print(f"regenerated {len(cases)} derived cases from base-debug-enclave + prod-1")


if __name__ == "__main__":
    main()
