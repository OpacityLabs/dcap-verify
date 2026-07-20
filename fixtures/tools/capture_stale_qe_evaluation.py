#!/usr/bin/env python3
"""
Capture the `prod-1-stale-qe-evaluation` fixture: prod-1's quote and collateral
with the signed tcbInfo swapped for the genuine Intel-signed EARLY-track tcbInfo
of the same FMSPC, fetched live from Intel PCS v4.

The early track runs ahead of the standard track's TCB evaluation round, so the
spliced collateral carries tcbInfo from a newer round than its qeIdentity. With
the floor pinned between the two rounds, the tcbInfo passes the floor and the
qeIdentity trips it — the only way to exercise the QE-identity leg of the
evaluation-round check end-to-end with Intel-signed data (both prod-1 documents
share one round, so the tcbInfo leg always fires first otherwise).

Needs network (Intel PCS). Aborts if the early track has not advanced past the
base collateral's round. The verification time is pinned at capture.

Run from the repo root:  python3 fixtures/tools/capture_stale_qe_evaluation.py
"""
import json, os, time, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FX = os.path.join(ROOT, "fixtures")
CASE = "prod-1-stale-qe-evaluation"


def splice_json_value(text, key):
    """Return (start, end) of the JSON value for `key` in `text`."""
    i = text.index(f'"{key}":') + len(f'"{key}":')
    while text[i] in " \t\r\n":
        i += 1
    _, end = json.JSONDecoder().raw_decode(text, i)
    return i, end


def main():
    base = os.path.join(FX, "prod-1")
    quote = open(os.path.join(base, "quote.bin"), "rb").read()
    collateral = open(os.path.join(base, "collateral.json")).read()
    base_meta = json.load(open(os.path.join(base, "meta.json")))

    base_doc = json.loads(collateral)
    fmspc = base_doc["tcb_info"]["tcbInfo"]["fmspc"]
    qe_round = base_doc["qe_identity"]["enclaveIdentity"]["tcbEvaluationDataNumber"]

    url = f"https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc={fmspc}&update=early"
    fetched = urllib.request.urlopen(url, timeout=30).read().decode()
    body = json.loads(fetched)
    tcb_round = body["tcbInfo"]["tcbEvaluationDataNumber"]
    if tcb_round <= qe_round:
        raise SystemExit(
            f"early-track tcbInfo round ({tcb_round}) has not advanced past the base "
            f"qeIdentity round ({qe_round}); the QE leg cannot be isolated — recapture later"
        )
    floor = qe_round + 1

    lo, hi = splice_json_value(collateral, "tcb_info")
    spliced = collateral[:lo] + fetched + collateral[hi:]

    now = int(time.time())
    d = os.path.join(FX, CASE)
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "quote.bin"), "wb").write(quote)
    open(os.path.join(d, "collateral.json"), "w").write(spliced)
    meta = {
        "case": CASE,
        "current_time_unix": now,
        "expected_mrenclave_hex": base_meta["expected_mrenclave_hex"],
        "verdict": "reject",
        "category": "qe-identity-stale",
        "min_tcb_evaluation_data_number": floor,
        "notes": f"prod-1 with its signed tcbInfo replaced byte-verbatim by the genuine Intel-signed EARLY-track tcbInfo (round {tcb_round}) for the same FMSPC, fetched from PCS v4 at capture. With the floor at {floor}, the round-{tcb_round} tcbInfo passes and the round-{qe_round} qeIdentity trips — pinning the QE-identity leg of the evaluation-round check end-to-end.",
    }
    with open(os.path.join(d, "meta.json"), "w") as f:
        json.dump(meta, f, indent=2)
        f.write("\n")
    print(f"captured {CASE}: tcbInfo round {tcb_round}, qeIdentity round {qe_round}, "
          f"floor {floor}, pinned time {now}")


if __name__ == "__main__":
    main()
