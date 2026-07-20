#!/usr/bin/env python3
"""
Capture a base dcap-verify oracle fixture from a live attestation endpoint + PCCS.

Fetches the attestation quote, derives FMSPC / PCK-CA / MRENCLAVE straight from
the quote's embedded PCK chain, pulls the matching FMSPC collateral from the
PCCS, and writes quote.bin + collateral.json + meta.json in the exact shape
dcap-verify consumes. The signed tcbInfo / enclaveIdentity bodies are stored
VERBATIM so their Intel signatures still verify; issuer chains come from the
response headers (URL-decoded); CRLs are converted hex-DER -> PEM.

The derived (mutation) cases are produced from the two bases by
derive_fixtures.py; this script only (re)captures a base.

Examples (uses curl, so self-signed PCCS certs work via -k):
    # debug base
    python3 fixtures/tools/capture_base.py --out fixtures/base-debug-enclave \\
        --attest http://<attest-host>:<port> --pccs https://<pccs-host>:<port> \\
        --verdict reject --category debug-enclave-rejected
    # prod base (fill in tcb_standing after the first oracle run reports it)
    python3 fixtures/tools/capture_base.py --out fixtures/prod-1 \\
        --attest https://<attest-host>:<port> \\
        --pccs https://<pccs-host>:<port> --verdict accept
"""
import argparse, base64, json, os, re, struct, subprocess, time, urllib.parse

SGX_EXT_FMSPC_OID = bytes([0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x01, 0x0D, 0x01, 0x04])


def curl(url, dump_headers=None):
    cmd = ["curl", "-k", "-s", "-m", "30"]
    if dump_headers:
        cmd += ["-D", dump_headers]
    cmd += [url]
    return subprocess.run(cmd, capture_output=True, check=True).stdout


def header_value(hdr_path, name):
    txt = open(hdr_path, "r", errors="replace").read()
    for line in txt.splitlines():
        if line.lower().startswith(name.lower() + ":"):
            v = line.split(":", 1)[1].strip()
            return "\n".join(l.lstrip() for l in urllib.parse.unquote(v).splitlines())
    raise SystemExit(f"header {name} not found in {hdr_path}")


def der_crl_pem(body: bytes) -> str:
    der = bytes.fromhex(body.decode().strip().strip('"'))
    return "-----BEGIN X509 CRL-----\n" + base64.encodebytes(der).decode().strip() + "\n-----END X509 CRL-----\n"


def pck_fmspc_ca(quote: bytes):
    i = quote.find(b"-----BEGIN CERTIFICATE-----")
    leaf_pem = quote[i:].split(b"-----END CERTIFICATE-----", 1)[0] + b"-----END CERTIFICATE-----\n"
    der = subprocess.run(["openssl", "x509", "-outform", "DER"], input=leaf_pem,
                         capture_output=True, check=True).stdout
    j = der.find(SGX_EXT_FMSPC_OID) + len(SGX_EXT_FMSPC_OID)
    fmspc = der[j + 2 : j + 2 + der[j + 1]].hex()
    ca = "platform" if b"Platform CA" in der else "processor"
    return fmspc, ca


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--attest", required=True, help="scheme://host:port of the attestation endpoint (serves GET /attestation-quote)")
    ap.add_argument("--pccs", required=True, help="scheme://host:port of the PCCS")
    ap.add_argument("--verdict", choices=["accept", "reject"], required=True)
    ap.add_argument("--category", help="rejection category (when --verdict reject)")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    tmp = os.path.join(args.out, ".hdr")

    quote_hex = json.loads(curl(f"{args.attest.rstrip('/')}/attestation-quote"))["quote"]
    quote = bytes.fromhex(quote_hex[2:] if quote_hex.startswith("0x") else quote_hex)
    open(os.path.join(args.out, "quote.bin"), "wb").write(quote)
    assert struct.unpack_from("<H", quote, 0)[0] == 3, "not a v3 quote"
    mrenclave = quote[112:144].hex()
    fmspc, ca = pck_fmspc_ca(quote)
    print(f"mrenclave={mrenclave} fmspc={fmspc} ca={ca} debug={'yes' if quote[96] & 0x02 else 'no'}")

    pccs = args.pccs.rstrip("/")
    tcb_body = curl(f"{pccs}/sgx/certification/v4/tcb?fmspc={fmspc}", tmp).decode()
    tcb_chain = header_value(tmp, "TCB-Info-Issuer-Chain")
    qe_body = curl(f"{pccs}/sgx/certification/v4/qe/identity", tmp).decode()
    qe_chain = header_value(tmp, "SGX-Enclave-Identity-Issuer-Chain")
    pckcrl = curl(f"{pccs}/sgx/certification/v4/pckcrl?ca={ca}&encoding=pem", tmp)
    crl_chain = header_value(tmp, "SGX-PCK-CRL-Issuer-Chain")
    rootcrl = curl(f"{pccs}/sgx/certification/v4/rootcacrl")
    os.remove(tmp)

    def js(s):
        return json.dumps(s)

    collateral = (
        "{"
        '"version":3,'
        f'"root_ca_crl":{js(der_crl_pem(rootcrl))},'
        f'"pck_crl":{js(der_crl_pem(pckcrl))},'
        f'"tcb_info_issuer_chain":{js(tcb_chain)},'
        f'"pck_crl_issuer_chain":{js(crl_chain)},'
        f'"qe_identity_issuer_chain":{js(qe_chain)},'
        f'"tcb_info":{tcb_body},'
        f'"qe_identity":{qe_body}'
        "}"
    )
    p = json.loads(collateral)  # round-trips; signed sub-objects intact
    assert "tcbInfo" in p["tcb_info"] and "enclaveIdentity" in p["qe_identity"]
    open(os.path.join(args.out, "collateral.json"), "w").write(collateral)

    meta = {"case": os.path.basename(args.out.rstrip("/")),
            "current_time_unix": int(time.time()),
            "expected_mrenclave_hex": mrenclave, "verdict": args.verdict}
    if args.verdict == "reject":
        meta["category"] = args.category or "debug-enclave-rejected"
    else:
        # fill from the oracle test's first run, which prints the observed standing
        meta["tcb_standing"] = None
    with open(os.path.join(args.out, "meta.json"), "w") as f:
        json.dump(meta, f, indent=2)
        f.write("\n")
    print("wrote", args.out)


if __name__ == "__main__":
    main()
