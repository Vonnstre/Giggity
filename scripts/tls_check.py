#!/usr/bin/env python3
# scripts/tls_check.py
# Usage: python3 scripts/tls_check.py --targets admin-targets.txt --out out/raw/tls.jsonl

import argparse, ssl, socket, json
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from pathlib import Path
from datetime import datetime

ap = argparse.ArgumentParser()
ap.add_argument("--targets", required=True)
ap.add_argument("--out", required=True)
args = ap.parse_args()

Path(args.out).parent.mkdir(parents=True, exist_ok=True)

def fetch_cert(host, port=443, timeout=6):
    rec = {"host": host}
    try:
        pem = ssl.get_server_certificate((host, port))
        cert = x509.load_pem_x509_certificate(pem.encode(), default_backend())
        rec["not_before"] = cert.not_valid_before.isoformat()
        rec["not_after"] = cert.not_valid_after.isoformat()
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            rec["sands"] = san.value.get_values_for_type(x509.DNSName)
        except Exception:
            rec["sands"] = []
        rec["issuer"] = {x.oid._name: x.value for x in cert.issuer}
        rec["subject"] = {x.oid._name: x.value for x in cert.subject}
        rec["serial"] = str(cert.serial_number)
        rec["version"] = cert.version.name if hasattr(cert, "version") else None
    except Exception as e:
        rec["error"] = str(e)
    return rec

with open(args.targets) as f, open(args.out, "w") as out:
    for host in [l.strip() for l in f if l.strip() and not l.startswith("#")]:
        r = fetch_cert(host)
        out.write(json.dumps(r) + "\n")
print("[tls_check] done ->", args.out)
