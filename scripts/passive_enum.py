#!/usr/bin/env python3
"""
passive_enum.py
Safe, passive enumeration for in-scope hosts. Outputs JSONL per module into out/raw.
Usage:
  python3 scripts/passive_enum.py --targets targets.txt --out out
"""
import argparse, os, json, ssl, socket, subprocess, re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
import httpx
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from tqdm import tqdm

ap = argparse.ArgumentParser()
ap.add_argument("--targets", required=True, help="file with hosts, one per line")
ap.add_argument("--out", required=True)
ap.add_argument("--concurrency", type=int, default=6)
ap.add_argument("--ua", default="PassiveEnum/1.0")
args = ap.parse_args()

OUT = Path(args.out)
RAW = OUT/"raw"
EVID = OUT/"evidence"
for d in (RAW, EVID/"har", EVID/"screens"):
    d.mkdir(parents=True, exist_ok=True)

def read_targets(path):
    with open(path) as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]

def dns_info(host):
    rec = {"host":host, "module":"dns", "a":[], "aaaa":[], "cname_chain":[]}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5
    try:
        for r in resolver.resolve(host, "A"):
            rec["a"].append(r.to_text())
    except Exception:
        pass
    try:
        for r in resolver.resolve(host, "AAAA"):
            rec["aaaa"].append(r.to_text())
    except Exception:
        pass
    # follow CNAME chain
    cur = host
    tried = set()
    while True:
        try:
            ans = resolver.resolve(cur, "CNAME")
            target = ans[0].target.to_text().rstrip(".")
            if target in tried or target==cur: break
            rec["cname_chain"].append({"from":cur,"to":target})
            tried.add(target)
            cur = target
        except Exception:
            break
    return rec

def get_cert_info(host, port=443):
    rec = {"host":host, "module":"tls", "ok":False}
    try:
        # fetch pem via ssl.get_server_certificate
        pem = ssl.get_server_certificate((host, port))
        cert = x509.load_pem_x509_certificate(pem.encode(), default_backend())
        rec["ok"] = True
        rec["subject"] = {attr.oid._name: attr.value for attr in cert.subject}
        rec["issuer"] = {attr.oid._name: attr.value for attr in cert.issuer}
        rec["not_valid_before"] = cert.not_valid_before.isoformat()
        rec["not_valid_after"] = cert.not_valid_after.isoformat()
        rec["serial_number"] = str(cert.serial_number)
        # SANs
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            rec["sands"] = san_ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            rec["sands"] = []
        # pubkey
        pub = cert.public_key()
        rec["pubkey_type"] = type(pub).__name__
    except Exception as e:
        rec["error"] = str(e)
    return rec

COMMON_PATHS = [
    "/", "/.well-known/openid-configuration", "/.well-known/security.txt",
    "/openapi.json", "/swagger.json", "/health", "/status", "/metrics",
    "/robots.txt", "/sitemap.xml", "/api", "/v1", "/v2", "/graphql"
]

JS_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
KEY_PATTERNS = re.compile(r'(client_id|api_key|apiKey|api_key|redirect_uri|clientSecret|PRIVATE_KEY|ACCESS_KEY|SECRET_KEY)', re.I)

def http_probe(host):
    rec = {"host":host, "module":"http", "results":[]}
    headers = {"User-Agent": args.ua}
    client = httpx.Client(timeout=10.0, headers=headers, follow_redirects=True, verify=True)
    for p in COMMON_PATHS:
        url = f"https://{host}{p}"
        try:
            r = client.get(url)
            info = {"path":p,"status":r.status_code,"ct":r.headers.get("content-type",""), "len": len(r.content)}
            info["server"] = r.headers.get("server","")
            # save small snippet if text
            if "application/json" in r.headers.get("content-type","") or "text" in r.headers.get("content-type",""):
                info["snippet"] = (r.text or "")[:1000]
            rec["results"].append(info)
        except Exception as e:
            rec["results"].append({"path":p,"error":str(e)})
    # root parsing for JS
    try:
        r = client.get(f"https://{host}/", timeout=10.0)
        body = r.text or ""
        scripts = JS_SRC_RE.findall(body)
        js_found = []
        for s in scripts:
            s = s.strip()
            if s.startswith("//"): s = "https:" + s
            if s.startswith("/"): s = f"https://{host}{s}"
            if not s.lower().startswith("http"):
                continue
            try:
                j = client.get(s, timeout=10.0)
                txt = j.text or ""
                keys = KEY_PATTERNS.findall(txt)
                js_found.append({"url":s,"status":j.status_code,"len":len(j.content),"keys": list(set(keys))})
            except Exception:
                js_found.append({"url":s,"error":"fetch_failed"})
        rec["js"] = js_found
    except Exception:
        rec["js"] = []
    return rec

def headers_check(host):
    rec = {"host":host, "module":"headers"}
    headers = {"User-Agent": args.ua}
    try:
        with httpx.Client(timeout=8.0, headers=headers, follow_redirects=True, verify=True) as cli:
            r = cli.get(f"https://{host}")
            hx = {k.lower(): v for k, v in r.headers.items()}
            rec.update({
                "status": r.status_code,
                "csp": hx.get("content-security-policy",""),
                "xfo": hx.get("x-frame-options",""),
                "hsts": hx.get("strict-transport-security",""),
                "cors": hx.get("access-control-allow-origin",""),
                "acac": hx.get("access-control-allow-credentials",""),
                "server": hx.get("server",""),
                "via": hx.get("via",""),
                "xcache": hx.get("x-cache",""),
                "xserved": hx.get("x-served-by","")
            })
    except Exception as e:
        rec["error"] = str(e)
    return rec

def discovery_probe(host):
    # probe likely API endpoints and collect ones that return 200/2xx
    out = {"host":host, "module":"discovered_apis", "endpoints":[]}
    client = httpx.Client(timeout=8.0, follow_redirects=True, verify=True, headers={"User-Agent":args.ua})
    paths = ["/api", "/api/v1", "/api/v2", "/v1", "/v2", "/graphql", "/health", "/status", "/openapi.json", "/swagger.json"]
    for p in paths:
        url = f"https://{host}{p}"
        try:
            r = client.get(url)
            if r.status_code in (200,201,202,203,206):
                out["endpoints"].append({"url":url,"status":r.status_code,"ct":r.headers.get("content-type","")})
        except Exception:
            pass
    return out

def options_cors_probe(host, endpoints):
    out = {"host":host, "module":"cors", "results":[]}
    client = httpx.Client(timeout=8.0, headers={"User-Agent":args.ua})
    for ep in endpoints:
        try:
            r = client.options(ep, headers={"Origin":"http://evil.example","Access-Control-Request-Method":"GET"})
            aco = r.headers.get("Access-Control-Allow-Origin","")
            acac = r.headers.get("Access-Control-Allow-Credentials","")
            if aco or acac:
                out["results"].append({"url":ep,"status":r.status_code,"aco":aco,"acac":acac})
        except Exception:
            pass
    return out

def process_host(host):
    items=[]
    items.append(dns_info(host))
    items.append(get_cert_info(host))
    items.append(headers_check(host))
    items.append(http_probe(host))
    disc = discovery_probe(host)
    items.append(disc)
    # build endpoints list for CORS: use discovered endpoints (paths) + common endpoints
    endpoints = [e["url"] for e in disc.get("endpoints",[])]
    # add common API-ish endpoints
    for p in ["/api","/v1","/v2","/graphql","/health","/status"]:
        endpoints.append(f"https://{host}{p}")
    corsr = options_cors_probe(host, list(set(endpoints)))
    items.append(corsr)
    return items

def write_jsonl(items, outdir):
    for rec in items:
        module = rec.get("module","misc")
        p = RAW/f"{module}.jsonl"
        with open(p, "a") as w:
            w.write(json.dumps(rec, default=str) + "\n")

def main():
    targets = read_targets(args.targets)
    all_results=[]
    with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futures = {ex.submit(process_host, t): t for t in targets}
        for fut in tqdm(as_completed(futures), total=len(futures), desc="hosts"):
            t = futures[fut]
            try:
                res = fut.result()
                write_jsonl(res, RAW)
                all_results.extend(res)
            except Exception as e:
                print(f"[!] host {t} failed: {e}")
    # aggregate small triage csv (simple)
    csvp = OUT/"triage.csv"
    with open(csvp,"w") as f:
        f.write("host,module,summary\n")
        for r in all_results:
            host = r.get("host","")
            module = r.get("module","")
            if module=="tls":
                sumry = f"not_after={r.get('not_valid_after','')}"
            elif module=="http":
                sumry = ";".join([f"{it.get('path')}={it.get('status')}" for it in r.get("results",[])][:5])
            else:
                sumry = ""
            f.write(f"{host},{module},{summary_escape(sumry)}\n")
    print("[done] outputs in:", OUT)

def summary_escape(s):
    return s.replace("\n"," ").replace(",",";")

if __name__=="__main__":
    main()
