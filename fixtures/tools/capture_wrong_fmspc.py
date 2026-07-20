#!/usr/bin/env python3
"""
Capture the `tcb-info-wrong-fmspc` fixture: prod-1's quote and collateral with
the signed tcbInfo swapped for a genuine Intel-signed one belonging to a
DIFFERENT platform family (FMSPC), fetched live from Intel PCS v4.

The fetched document is spliced into the collateral byte-verbatim, so Intel's
signature over it still verifies; the verifier must then reject because the
tcbInfo does not describe the quote's platform (fmspc mismatch,
tcb-level-unsupported). Everything else in the collateral stays byte-identical
to prod-1 so no other signature is disturbed.

Needs network (Intel PCS). The verification time is pinned at capture, so the
committed fixture stays valid forever; rerunning refreshes the document and
the pinned time together.

Run from the repo root:  python3 fixtures/tools/capture_wrong_fmspc.py
"""
import json, os, time, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FX = os.path.join(ROOT, "fixtures")
CASE = "tcb-info-wrong-fmspc"

# Any real FMSPC other than prod-1's 00A067110000 works; this one is a common
# Coffee Lake family also used in the dcap-differ recombination corpus.
WRONG_FMSPC = "00906ED50000"
PCS_URL = f"https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc={WRONG_FMSPC}"


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

    fetched = urllib.request.urlopen(PCS_URL, timeout=30).read().decode()
    body = json.loads(fetched)
    got = body["tcbInfo"]["fmspc"].upper()
    if got != WRONG_FMSPC:
        raise SystemExit(f"PCS returned fmspc {got}, expected {WRONG_FMSPC}")

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
        "category": "tcb-level-unsupported",
        "notes": f"prod-1 with its signed tcbInfo replaced byte-verbatim by the genuine Intel-signed tcbInfo for foreign FMSPC {WRONG_FMSPC}, fetched from PCS v4 at capture. Intel's signature over the document verifies; the fmspc gate must reject it. Time pinned at capture so the fetched document's own issueDate/nextUpdate window is satisfied.",
    }
    with open(os.path.join(d, "meta.json"), "w") as f:
        json.dump(meta, f, indent=2)
        f.write("\n")
    print(f"captured {CASE}: fmspc {got}, tcbEvaluationDataNumber "
          f"{body['tcbInfo']['tcbEvaluationDataNumber']}, pinned time {now}")


if __name__ == "__main__":
    main()
