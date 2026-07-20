#!/usr/bin/env python3
"""Regenerable generator for the DCAP recombination differential corpus.

Everything here is built from GENUINE Intel-signed artifacts fetched live from
Intel PCS v4, recombined in adversarial ways. No synthetic signing and no byte
mutation of any signature-covered body -- the whole point is that every quote,
tcbInfo, enclaveIdentity, CRL and certificate carries a real Intel signature;
only the *arrangement* of the pieces is hostile.

The script:
  1. fetches PCS artifacts into  dcap-differ/corpus/.pcs-cache/  (cached),
  2. emits case directories under dcap-differ/corpus/<case>/ each holding
     quote.bin, collateral.json (byte-exact splice) and meta.json.

collateral.json is assembled by *byte* concatenation so the tcbInfo /
enclaveIdentity response bodies are embedded verbatim (their p256 signatures
cover the raw body bytes -- reserializing through a JSON library would reorder
keys / restyle whitespace and destroy the signatures). Every emitted file is
re-parsed and the two signed slots are byte-compared against their sources.

stdlib + openssl CLI only.
"""

import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
DIFFER = os.path.dirname(HERE)
REPO = os.path.dirname(DIFFER)
FIX = os.path.join(REPO, "fixtures")
CORPUS = os.path.join(DIFFER, "corpus")
CACHE = os.path.join(CORPUS, ".pcs-cache")

PCS = "https://api.trustedservices.intel.com"
CERTS = "https://certificates.trustedservices.intel.com"

BASE_FMSPC = "00a067110000"          # prod-1 platform family / PCK Processor CA
WRONG_FMSPC = ["00906ed50000", "00806f050000"]
TDX_FMSPC = "90c06f000000"

# ----------------------------------------------------------------------------
# fetch layer (cached)
# ----------------------------------------------------------------------------

def _http(url):
    req = urllib.request.Request(url, headers={"User-Agent": "dcap-recombination-corpus/1.0"})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=45) as r:
                return r.status, r.read(), dict(r.headers.items())
        except Exception as e:  # noqa: BLE001
            if attempt == 3:
                raise
            print(f"  retry {attempt+1} for {url}: {e}", file=sys.stderr)
    raise RuntimeError("unreachable")


def _cache(label, url, chain_header=None):
    """Fetch url once; cache body (+ decoded issuer chain) under CACHE/label.*"""
    os.makedirs(CACHE, exist_ok=True)
    body_p = os.path.join(CACHE, label + ".body")
    chain_p = os.path.join(CACHE, label + ".chain")
    if os.path.exists(body_p) and (chain_header is None or os.path.exists(chain_p)):
        body = open(body_p, "rb").read()
        chain = open(chain_p).read() if chain_header else None
        return body, chain
    st, body, hdrs = _http(url)
    if st != 200:
        raise RuntimeError(f"{label}: {url} -> HTTP {st}: {body[:120]!r}")
    open(body_p, "wb").write(body)
    chain = None
    if chain_header:
        raw = hdrs.get(chain_header)
        if not raw:
            raise RuntimeError(f"{label}: missing header {chain_header}")
        chain = urllib.parse.unquote(raw)
        open(chain_p, "w").write(chain)
    return body, chain


def fetch_tcb(fmspc, evalnum=None, update=None, label=None):
    q = f"fmspc={fmspc}"
    if evalnum is not None:
        q += f"&tcbEvaluationDataNumber={evalnum}"
    if update is not None:
        q += f"&update={update}"
    lbl = label or f"tcb-{fmspc}-{evalnum or update or 'default'}"
    return _cache(lbl, f"{PCS}/sgx/certification/v4/tcb?{q}", "TCB-Info-Issuer-Chain")


def fetch_qe(evalnum=None, update=None, label=None):
    q = []
    if evalnum is not None:
        q.append(f"tcbEvaluationDataNumber={evalnum}")
    if update is not None:
        q.append(f"update={update}")
    qs = ("?" + "&".join(q)) if q else ""
    lbl = label or f"qe-{evalnum or update or 'default'}"
    return _cache(lbl, f"{PCS}/sgx/certification/v4/qe/identity{qs}",
                  "SGX-Enclave-Identity-Issuer-Chain")


def fetch_qve():
    return _cache("qve-identity", f"{PCS}/sgx/certification/v4/qve/identity",
                  "SGX-Enclave-Identity-Issuer-Chain")


def fetch_tdx_tcb(fmspc):
    return _cache(f"tdxtcb-{fmspc}", f"{PCS}/tdx/certification/v4/tcb?fmspc={fmspc}",
                  "TCB-Info-Issuer-Chain")


def fetch_pckcrl(ca):
    return _cache(f"pckcrl-{ca}",
                  f"{PCS}/sgx/certification/v4/pckcrl?ca={ca}&encoding=pem",
                  "SGX-PCK-CRL-Issuer-Chain")


def fetch_rootcacrl():
    body, _ = _cache("rootcacrl", f"{CERTS}/IntelSGXRootCA.crl")
    return body.decode("ascii")


# ----------------------------------------------------------------------------
# byte-exact JSON helpers
# ----------------------------------------------------------------------------

def extract_raw_object(buf, key):
    """Return the exact bytes of the object value for top-level `key` in buf."""
    token = ('"%s"' % key).encode()
    i = buf.find(token)
    if i < 0:
        raise KeyError(key)
    i += len(token)
    while buf[i:i + 1] in (b" ", b"\t", b"\r", b"\n"):
        i += 1
    assert buf[i:i + 1] == b":", f"{key} not a key"
    i += 1
    while buf[i:i + 1] in (b" ", b"\t", b"\r", b"\n"):
        i += 1
    assert buf[i:i + 1] == b"{", f"{key} value is not an object"
    start = i
    depth = 0
    in_str = False
    esc = False
    while i < len(buf):
        c = buf[i]
        if in_str:
            if esc:
                esc = False
            elif c == 0x5C:  # backslash
                esc = True
            elif c == 0x22:  # quote
                in_str = False
        else:
            if c == 0x22:
                in_str = True
            elif c == 0x7B:  # {
                depth += 1
            elif c == 0x7D:  # }
                depth -= 1
                if depth == 0:
                    return buf[start:i + 1]
        i += 1
    raise ValueError("unbalanced object for " + key)


def jstr(s):
    """JSON-encode a Python string to bytes (used for the PEM string fields)."""
    return json.dumps(s).encode("utf-8")


def assemble_collateral(root_ca_crl, pck_crl, tcb_chain, pckcrl_chain, qe_chain,
                        tcb_info_raw, qe_identity_raw):
    """Splice a collateral.json by byte concatenation; signed slots verbatim."""
    return (
        b"{"
        + b'"version":3,'
        + b'"root_ca_crl":' + jstr(root_ca_crl) + b","
        + b'"pck_crl":' + jstr(pck_crl) + b","
        + b'"tcb_info_issuer_chain":' + jstr(tcb_chain) + b","
        + b'"pck_crl_issuer_chain":' + jstr(pckcrl_chain) + b","
        + b'"qe_identity_issuer_chain":' + jstr(qe_chain) + b","
        + b'"tcb_info":' + tcb_info_raw + b","
        + b'"qe_identity":' + qe_identity_raw
        + b"}"
    )


# ----------------------------------------------------------------------------
# date helpers
# ----------------------------------------------------------------------------

def iso_to_unix(s):
    # PCS JSON uses 'YYYY-MM-DDTHH:MM:SSZ'; openssl -dateopt iso_8601 uses a
    # space separator ('YYYY-MM-DD HH:MM:SSZ'). Accept both.
    s = s.strip().replace(" ", "T")
    return int(dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")
               .replace(tzinfo=dt.timezone.utc).timestamp())


def unix_to_iso(u):
    return dt.datetime.fromtimestamp(u, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def doc_dates(body):
    d = json.loads(body)
    o = d.get("tcbInfo") or d.get("enclaveIdentity")
    return iso_to_unix(o["issueDate"]), iso_to_unix(o["nextUpdate"])


def cert_dates_from_pem(pem_text):
    """Return list of (subject, notBefore_unix, notAfter_unix) for each cert."""
    out = []
    blocks = pem_text.split("-----END CERTIFICATE-----")
    for b in blocks:
        if "BEGIN CERTIFICATE" not in b:
            continue
        one = b[b.index("-----BEGIN CERTIFICATE-----"):] + "-----END CERTIFICATE-----\n"
        r = subprocess.run(
            ["openssl", "x509", "-noout", "-subject", "-dates",
             "-dateopt", "iso_8601"],
            input=one.encode(), capture_output=True)
        txt = r.stdout.decode()
        subj = nb = na = None
        for line in txt.splitlines():
            if line.startswith("subject="):
                subj = line[len("subject="):]
            elif line.startswith("notBefore="):
                nb = iso_to_unix(line[len("notBefore="):])
            elif line.startswith("notAfter="):
                na = iso_to_unix(line[len("notAfter="):])
        if subj is not None:
            out.append((subj, nb, na))
    return out


def crl_dates(pem_text):
    r = subprocess.run(
        ["openssl", "crl", "-noout", "-lastupdate", "-nextupdate",
         "-dateopt", "iso_8601"],
        input=pem_text.encode(), capture_output=True)
    txt = r.stdout.decode()
    this_u = next_u = None
    for line in txt.splitlines():
        if line.startswith("lastUpdate="):
            this_u = iso_to_unix(line[len("lastUpdate="):])
        elif line.startswith("nextUpdate="):
            next_u = iso_to_unix(line[len("nextUpdate="):])
    return this_u, next_u


# ----------------------------------------------------------------------------
# case emission
# ----------------------------------------------------------------------------

def write_case(name, quote_bytes, collateral_bytes, current_time, verdict, notes,
               category=None, tcb_standing=None):
    d = os.path.join(CORPUS, name)
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "quote.bin"), "wb").write(quote_bytes)
    open(os.path.join(d, "collateral.json"), "wb").write(collateral_bytes)
    meta = {"current_time_unix": current_time, "verdict": verdict, "notes": notes}
    if category:
        meta["category"] = category
    if tcb_standing:
        meta["tcb_standing"] = tcb_standing
    open(os.path.join(d, "meta.json"), "w").write(json.dumps(meta, indent=2) + "\n")


def verify_case(name, tcb_info_raw, qe_identity_raw):
    """Re-parse the emitted collateral and byte-compare the two signed slots."""
    p = os.path.join(CORPUS, name, "collateral.json")
    buf = open(p, "rb").read()
    json.loads(buf)  # must be valid JSON
    got_tcb = extract_raw_object(buf, "tcb_info")
    got_qe = extract_raw_object(buf, "qe_identity")
    if got_tcb != tcb_info_raw:
        raise AssertionError(f"{name}: tcb_info bytes not verbatim")
    if got_qe != qe_identity_raw:
        raise AssertionError(f"{name}: qe_identity bytes not verbatim")


# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------

def main():
    # ---- load base fixture components ------------------------------------
    prod_quote = open(os.path.join(FIX, "prod-1", "quote.bin"), "rb").read()
    debug_quote = open(os.path.join(FIX, "base-debug-enclave", "quote.bin"), "rb").read()
    base_buf = open(os.path.join(FIX, "prod-1", "collateral.json"), "rb").read()
    base = json.loads(base_buf)
    B_root_crl = base["root_ca_crl"]
    B_pck_crl = base["pck_crl"]
    B_tcb_chain = base["tcb_info_issuer_chain"]
    B_pckcrl_chain = base["pck_crl_issuer_chain"]
    B_qe_chain = base["qe_identity_issuer_chain"]
    B_tcb_raw = extract_raw_object(base_buf, "tcb_info")
    B_qe_raw = extract_raw_object(base_buf, "qe_identity")

    STANDING_CSW = {"configuration-and-sw-hardening-needed":
                    {"advisory_ids": ["INTEL-SA-00289", "INTEL-SA-00615"]}}

    # ---- fetch live artifacts -------------------------------------------
    print("fetching PCS artifacts (cached under corpus/.pcs-cache/) ...")
    EVALS = ["19", "20", "21"]
    tcb = {}   # variant -> (body, chain)
    qe = {}
    for ev in EVALS:
        tcb[ev] = fetch_tcb(BASE_FMSPC, evalnum=ev)
        qe[ev] = fetch_qe(evalnum=ev)
    tcb["early"] = fetch_tcb(BASE_FMSPC, update="early", label="tcb-early")
    tcb["standard"] = fetch_tcb(BASE_FMSPC, update="standard", label="tcb-standard")
    qe["early"] = fetch_qe(update="early", label="qe-early")
    qe["standard"] = fetch_qe(update="standard", label="qe-standard")

    qve_body, qve_chain = fetch_qve()
    tdx_body, tdx_chain = fetch_tdx_tcb(TDX_FMSPC)
    wrong = {f: fetch_tcb(f, label=f"tcb-{f}") for f in WRONG_FMSPC}

    crl_proc_body, crl_proc_chain = fetch_pckcrl("processor")
    crl_plat_body, crl_plat_chain = fetch_pckcrl("platform")
    crl_proc = crl_proc_body.decode("ascii")
    crl_plat = crl_plat_body.decode("ascii")
    root_crl_live = fetch_rootcacrl()

    def raw(kind_body):
        """Wrap a fetched envelope body (already {tcbInfo/enclaveIdentity,sig})."""
        return kind_body  # bytes, verbatim

    VARIANTS = EVALS + ["early", "standard"]

    # convenience: time = doc issueDate + 1h
    def t_plus1h(body):
        return doc_dates(body)[0] + 3600

    emitted = []  # (name, tcb_info_raw, qe_identity_raw) for verification

    # ==== SANITY CONTROL : fresh eval-19 (matches base) spliced by us =====
    # Unrecombined: fresh PCS fetch of the SAME fmspc/eval as the base, run
    # through this pipeline. Must come out agree-accept (or a known delta)
    # before any recombination result is trusted.
    _tb19, _tc19 = tcb["19"]
    _qb19, _qc19 = qe["19"]
    _tctrl = max(doc_dates(_tb19)[0], doc_dates(_qb19)[0]) + 3600

    def emit(name, quote, root_crl, pck_crl, tcb_chain, pckcrl_chain, qe_chain,
             tcb_info_raw, qe_info_raw, t, verdict, notes, category=None, standing=None):
        col = assemble_collateral(root_crl, pck_crl, tcb_chain, pckcrl_chain,
                                  qe_chain, tcb_info_raw, qe_info_raw)
        write_case(name, quote, col, t, verdict, notes, category, standing)
        emitted.append((name, tcb_info_raw, qe_info_raw))

    emit("control-fresh-eval19", prod_quote, root_crl_live, crl_proc,
         _tc19, crl_proc_chain, _qc19, raw(_tb19), raw(_qb19), _tctrl,
         "accept",
         "SANITY CONTROL: fresh eval-19 tcbInfo + qe_identity (same fmspc/eval as "
         "the base), live proc+root CRL, spliced by this pipeline; "
         f"time={unix_to_iso(_tctrl)}. Unrecombined -> MUST be agree-accept.",
         standing=STANDING_CSW)

    # ==== FAMILY A : eval-number matrix (genuine TCB-level selection) =====
    for v in VARIANTS:
        tb, tc = tcb[v]
        t = t_plus1h(tb)
        emit(f"tA-tcb-{v}", prod_quote, root_crl_live, crl_proc,
             tc, crl_proc_chain, B_qe_chain, raw(tb), B_qe_raw, t,
             "accept",
             f"FAMILY A: fresh tcbInfo eval={v} in tcb slot, base(eval19) qe_identity; "
             f"time=tcbInfo.issueDate+1h={unix_to_iso(t)}; live proc+root CRL. "
             "Platform standing is eval-invariant here -> EXPECTED agree-accept.",
             standing=STANDING_CSW)
    for v in VARIANTS:
        qb, qc = qe[v]
        t = t_plus1h(qb)
        emit(f"tA-qe-{v}", prod_quote, root_crl_live, crl_proc,
             B_tcb_chain, crl_proc_chain, qc, B_tcb_raw, raw(qb), t,
             "accept",
             f"FAMILY A: fresh qe_identity eval={v} in qe slot, base(eval19) tcbInfo; "
             f"time=qe.issueDate+1h={unix_to_iso(t)}; live proc+root CRL. "
             "EXPECTED agree-accept (QE UpToDate at isvsvn 11 for all evals).",
             standing=STANDING_CSW)
    for v in VARIANTS:
        tb, tc = tcb[v]
        qb, qc = qe[v]
        t = max(doc_dates(tb)[0], doc_dates(qb)[0]) + 3600
        emit(f"tA-both-{v}", prod_quote, root_crl_live, crl_proc,
             tc, crl_proc_chain, qc, raw(tb), raw(qb), t,
             "accept",
             f"FAMILY A: both tcbInfo and qe_identity fresh eval={v} (matched); "
             f"time=max(issueDate)+1h={unix_to_iso(t)}; live proc+root CRL. "
             "EXPECTED agree-accept.",
             standing=STANDING_CSW)
    # [x2] base-debug twins for the plain eval-19/20/21 tcbInfo cases
    for v in EVALS:
        tb, tc = tcb[v]
        t = t_plus1h(tb)
        emit(f"tA-tcb-{v}-debug", debug_quote, root_crl_live, crl_proc,
             tc, crl_proc_chain, B_qe_chain, raw(tb), B_qe_raw, t,
             "reject",
             f"FAMILY A twin: DEBUG quote, fresh tcbInfo eval={v}, base qe_identity; "
             f"time={unix_to_iso(t)}. Every stage passes to the debug gate. "
             "EXPECTED known-delta(debug-gate) (dcap debug-reject, QVL accepts).",
             category="debug-enclave-rejected")

    # ==== FAMILY B : wrong-FMSPC tcbInfo vs prod-1 quote =================
    for f in WRONG_FMSPC:
        wb, wc = wrong[f]
        t = t_plus1h(wb)
        emit(f"tB-fmspc-{f}", prod_quote, root_crl_live, crl_proc,
             wc, crl_proc_chain, B_qe_chain, raw(wb), B_qe_raw, t,
             "reject",
             f"FAMILY B: genuine tcbInfo for FMSPC {f} spliced against the prod-1 "
             f"quote (PCK FMSPC 00a067110000); time={unix_to_iso(t)}. QVL hard-rejects "
             "(TCBINFO_MISMATCH). EXPECTED agree-reject; a dcap ACCEPT is DANGEROUS.",
             category="tcb-level-unsupported")
        emit(f"tB-fmspc-{f}-debug", debug_quote, root_crl_live, crl_proc,
             wc, crl_proc_chain, B_qe_chain, raw(wb), B_qe_raw, t,
             "reject",
             f"FAMILY B twin: DEBUG quote + wrong-FMSPC {f} tcbInfo; time={unix_to_iso(t)}. "
             "EXPECTED agree-reject (dcap hits debug gate before fmspc; QVL mismatch).",
             category="debug-enclave-rejected")

    # ==== FAMILY C : sibling-CA CRL substitution =========================
    t_now = t_plus1h(tcb["19"][0])
    emit("tC-crl-platform-full", prod_quote, root_crl_live, crl_plat,
         B_tcb_chain, crl_plat_chain, B_qe_chain, B_tcb_raw, B_qe_raw, t_now,
         "reject",
         "FAMILY C: platform-CA pck_crl + platform-CA issuer chain substituted for "
         "the processor-CA pair (quote PCK is Processor CA). EXPECTED agree-reject; "
         "a dcap ACCEPT is DANGEROUS (sibling-CA CRL substitution).",
         category="crl-invalid")
    emit("tC-crl-platform-body-processor-chain", prod_quote, root_crl_live, crl_plat,
         B_tcb_chain, crl_proc_chain, B_qe_chain, B_tcb_raw, B_qe_raw, t_now,
         "reject",
         "FAMILY C: platform-CA pck_crl body with processor-CA issuer chain (half-swap). "
         "EXPECTED agree-reject; dcap ACCEPT is DANGEROUS.",
         category="crl-invalid")
    emit("tC-crl-processor-body-platform-chain", prod_quote, root_crl_live, crl_proc,
         B_tcb_chain, crl_plat_chain, B_qe_chain, B_tcb_raw, B_qe_raw, t_now,
         "reject",
         "FAMILY C: processor-CA pck_crl body with platform-CA issuer chain (half-swap). "
         "EXPECTED agree-reject; dcap ACCEPT is DANGEROUS.",
         category="crl-invalid")

    # ==== FAMILY D : slot swaps of genuine documents =====================
    # qe envelope in the tcb slot
    emit("tD-qe-in-tcb-slot", prod_quote, root_crl_live, crl_proc,
         B_tcb_chain, crl_proc_chain, B_qe_chain, B_qe_raw, B_qe_raw, t_now,
         "reject",
         "FAMILY D: base enclaveIdentity envelope placed in the tcb_info slot. "
         "EXPECTED agree-reject (dcap collateral-parse: missing tcbInfo field).",
         category="collateral-parse-error")
    # tcb envelope in the qe slot
    emit("tD-tcb-in-qe-slot", prod_quote, root_crl_live, crl_proc,
         B_tcb_chain, crl_proc_chain, B_qe_chain, B_tcb_raw, B_tcb_raw, t_now,
         "reject",
         "FAMILY D: base tcbInfo envelope placed in the qe_identity slot. "
         "EXPECTED agree-reject (dcap collateral-parse: missing enclaveIdentity).",
         category="collateral-parse-error")
    # qve/identity as qe_identity
    emit("tD-qve-as-qe", prod_quote, root_crl_live, crl_proc,
         B_tcb_chain, crl_proc_chain, qve_chain, B_tcb_raw, raw(qve_body), t_now,
         "reject",
         "FAMILY D: genuine QVE enclaveIdentity spliced into the qe_identity slot "
         "(id=QVE). EXPECTED agree-reject (dcap qe-identity-mismatch id!=QE); "
         "a dcap ACCEPT is DANGEROUS.",
         category="qe-identity-mismatch")
    # TDX tcbInfo as tcb_info
    emit("tD-tdx-tcb-as-tcb", prod_quote, root_crl_live, crl_proc,
         tdx_chain, crl_proc_chain, B_qe_chain, raw(tdx_body), B_qe_raw, t_now,
         "reject",
         "FAMILY D: genuine TDX tcbInfo (id=TDX) spliced into the SGX tcb_info slot. "
         "EXPECTED agree-reject; a dcap ACCEPT is DANGEROUS.",
         category="collateral-parse-error")
    # root_ca_crl and pck_crl swapped
    emit("tD-crl-swap", prod_quote, B_pck_crl, B_root_crl,
         B_tcb_chain, crl_proc_chain, B_qe_chain, B_tcb_raw, B_qe_raw, t_now,
         "reject",
         "FAMILY D: root_ca_crl and pck_crl swapped with each other. "
         "EXPECTED agree-reject (dcap crl-invalid: issuer mismatch).",
         category="crl-invalid")

    # ==== FAMILY E : chain recombinations (PEM string fields only) =======
    def certs_of(pem_text):
        parts, cur = [], []
        for line in pem_text.splitlines():
            cur.append(line)
            if "END CERTIFICATE" in line:
                parts.append("\n".join(cur).strip() + "\n")
                cur = []
        return parts

    tcb_certs = certs_of(B_tcb_chain)      # [TCB Signing leaf, Root]
    qe_certs = certs_of(B_qe_chain)
    pckcrl_certs = certs_of(B_pckcrl_chain)  # [PCK Processor CA, Root]

    leaf_only_tcb = tcb_certs[0]
    root_twice_tcb = "".join([tcb_certs[0], tcb_certs[1], tcb_certs[1]])
    reversed_tcb = "".join(list(reversed(tcb_certs)))
    leaf_only_qe = qe_certs[0]
    root_twice_pckcrl = "".join([pckcrl_certs[0], pckcrl_certs[1], pckcrl_certs[1]])

    emit("tE-tcbchain-is-pckcrlchain", prod_quote, root_crl_live, crl_proc,
         B_pckcrl_chain, crl_proc_chain, B_qe_chain, B_tcb_raw, B_qe_raw, t_now,
         "reject",
         "FAMILY E: tcb_info_issuer_chain replaced by the pck_crl_issuer_chain "
         "(leaf is PCK Processor CA, not TCB Signing). EXPECTED agree-reject "
         "(dcap root-ca-untrusted, signer-identity pin); a dcap ACCEPT is DANGEROUS.",
         category="root-ca-untrusted")
    emit("tE-tcbchain-leaf-only", prod_quote, root_crl_live, crl_proc,
         leaf_only_tcb, crl_proc_chain, B_qe_chain, B_tcb_raw, B_qe_raw, t_now,
         "reject",
         "FAMILY E: tcb_info_issuer_chain with the Root CA dropped (leaf only). "
         "Probes whether the verifier anchors on a supplied root. EXPECTED "
         "dcap reject(root-ca-untrusted); QVL behaviour maps slot tolerance.",
         category="root-ca-untrusted")
    emit("tE-tcbchain-root-twice", prod_quote, root_crl_live, crl_proc,
         root_twice_tcb, crl_proc_chain, B_qe_chain, B_tcb_raw, B_qe_raw, t_now,
         "accept",
         "FAMILY E: tcb_info_issuer_chain with the Root CA appended twice "
         "[leaf, root, root]. EXPECTED agree-accept (both tolerate a duplicated "
         "self-signed root).",
         standing=STANDING_CSW)
    emit("tE-tcbchain-reversed", prod_quote, root_crl_live, crl_proc,
         reversed_tcb, crl_proc_chain, B_qe_chain, B_tcb_raw, B_qe_raw, t_now,
         "reject",
         "FAMILY E: tcb_info_issuer_chain order reversed [root, leaf]. EXPECTED "
         "dcap reject(root-ca-untrusted: terminal cert not the pinned root); "
         "maps whether QVL reorders.",
         category="root-ca-untrusted")
    emit("tE-qechain-leaf-only", prod_quote, root_crl_live, crl_proc,
         B_tcb_chain, crl_proc_chain, leaf_only_qe, B_tcb_raw, B_qe_raw, t_now,
         "reject",
         "FAMILY E: qe_identity_issuer_chain with the Root CA dropped (leaf only). "
         "EXPECTED dcap reject(root-ca-untrusted); maps QE-chain slot tolerance.",
         category="root-ca-untrusted")
    emit("tE-pckcrlchain-root-twice", prod_quote, root_crl_live, crl_proc,
         B_tcb_chain, root_twice_pckcrl, B_qe_chain, B_tcb_raw, B_qe_raw, t_now,
         "accept",
         "FAMILY E: pck_crl_issuer_chain with the Root CA appended twice. "
         "EXPECTED agree-accept (duplicate root tolerated in the PCK-CRL slot).",
         standing=STANDING_CSW)

    # ==== FAMILY F : boundary times (UNMODIFIED prod-1 collateral) ========
    boundaries = {}  # label -> unix

    def add(label, u):
        if u is not None:
            boundaries[label] = u

    ti_u = doc_dates(B_tcb_raw)
    qi_u = doc_dates(B_qe_raw)
    add("tcbinfo-issuedate", ti_u[0])
    add("tcbinfo-nextupdate", ti_u[1])
    add("qeid-issuedate", qi_u[0])
    add("qeid-nextupdate", qi_u[1])
    rc = crl_dates(B_root_crl)
    pc = crl_dates(B_pck_crl)
    add("rootcrl-thisupdate", rc[0])
    add("rootcrl-nextupdate", rc[1])
    add("pckcrl-thisupdate", pc[0])
    add("pckcrl-nextupdate", pc[1])
    # certificate boundaries: dedup distinct certs across every chain incl. quote PCK
    i = prod_quote.find(b"-----BEGIN CERTIFICATE-----")
    quote_pck_pem = prod_quote[i:].split(b"\x00")[0].decode("ascii", "replace")
    seen = set()
    for pem_text in [B_tcb_chain, B_pckcrl_chain, B_qe_chain, quote_pck_pem]:
        for subj, nb, na in cert_dates_from_pem(pem_text):
            slug = subj.split("CN=")[-1].split(",")[0].strip().lower().replace(" ", "-")
            if (slug, nb, na) in seen:
                continue
            seen.add((slug, nb, na))
            add(f"cert-{slug}-notbefore", nb)
            add(f"cert-{slug}-notafter", na)

    # dedup identical unix values (keep first label), emit t-1 / t / t+1
    by_unix = {}
    for label, u in boundaries.items():
        by_unix.setdefault(u, label)
    for u, label in sorted(by_unix.items()):
        for suffix, tt in [("minus1", u - 1), ("eq", u), ("plus1", u + 1)]:
            name = f"tF-{label}-{suffix}"
            emit(name, prod_quote, B_root_crl, B_pck_crl,
                 B_tcb_chain, B_pckcrl_chain, B_qe_chain, B_tcb_raw, B_qe_raw, tt,
                 "boundary",
                 f"FAMILY F: unmodified prod-1 collateral at boundary '{label}' "
                 f"({unix_to_iso(u)}) {suffix} -> t={unix_to_iso(tt)}. Probes "
                 "<= vs < off-by-one between dcap window checks and QVL expiry model.")

    # ==== FAMILY G : tcbEvaluationDataNumber time-travel (fixed time) =====
    # All three evals at ONE fixed wall-clock; base(eval19) qe_identity paired.
    tg = max(doc_dates(tcb[e][0])[0] for e in EVALS) + 3600
    for v in EVALS:
        tb, tc = tcb[v]
        emit(f"tG-tcb-e{v}-qe-base", prod_quote, root_crl_live, crl_proc,
             tc, crl_proc_chain, B_qe_chain, raw(tb), B_qe_raw, tg,
             "accept",
             f"FAMILY G: tcbInfo eval={v} evaluated at a single fixed time "
             f"{unix_to_iso(tg)}, paired with base(eval19) qe_identity. eval!=19 is a "
             "tcbInfo/qeIdentity evaluation-number MISMATCH. Platform standing is "
             "eval-invariant here so dcap accepts; watch whether QVL enforces "
             "eval-number agreement (dcap-accept + qvl-reject would be DANGEROUS).",
             standing=STANDING_CSW)

    # ---- verify every emitted signed slot is byte-verbatim ---------------
    for name, tr, qr in emitted:
        verify_case(name, tr, qr)
    print(f"emitted {len(emitted)} cases; all signed slots verified byte-verbatim.")


if __name__ == "__main__":
    # wipe case dirs (keep .pcs-cache) for a clean regenerate
    if os.path.isdir(CORPUS):
        for e in os.listdir(CORPUS):
            if e == ".pcs-cache":
                continue
            p = os.path.join(CORPUS, e)
            shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)
    os.makedirs(CORPUS, exist_ok=True)
    main()
