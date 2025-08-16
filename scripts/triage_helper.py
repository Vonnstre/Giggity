#!/usr/bin/env python3
# scripts/triage_helper.py
# Usage: python3 scripts/triage_helper.py --raw out/raw --out out/triage.txt
import argparse, json, glob
from pathlib import Path
ap = argparse.ArgumentParser()
ap.add_argument("--raw", required=True)
ap.add_argument("--out", required=True)
args = ap.parse_args()
Path(args.out).parent.mkdir(parents=True, exist_ok=True)

tls = list(open(f"{args.raw}/tls.jsonl").read().splitlines()) if Path(f"{args.raw}/tls.jsonl").exists() else []
cors = list(open(f"{args.raw}/cors.jsonl").read().splitlines()) if Path(f"{args.raw}/cors.jsonl").exists() else []
apis = list(open(f"{args.raw}/discovered_apis.jsonl").read().splitlines()) if Path(f"{args.raw}/discovered_apis.jsonl").exists() else []
sessions = list(open(f"{args.raw}/sessions.jsonl").read().splitlines()) if Path(f"{args.raw}/sessions.jsonl").exists() else []

out = []
out.append("TRIAGE SUMMARY\n=============\n")
out.append(f"TLS entries: {len(tls)}")
out.append(f"CORS results: {len(cors)}")
out.append(f"Discovered API endpoints: {len(apis)}")
out.append(f"Session captures: {len(sessions)}")
out.append("\nCORS HITS (raw):")
for l in cors:
    try: j=json.loads(l); out.append(f"- {j.get('host')} -> {j.get('results')}")
    except: out.append(f"- {l}")
out.append("\nAPIs (raw):")
for l in apis:
    try: j=json.loads(l); out.append(f"- {j.get('host')} -> {j.get('url')}")
    except: out.append(f"- {l}")
open(args.out,"w").write("\n".join(out))
print("[triage_helper] wrote", args.out)
