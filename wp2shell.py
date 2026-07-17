#!/usr/bin/env python3
# wp2shell exposure check (CVE-2026-63030 / CVE-2026-60137), non-destructive.
# Usage:
#   wp2shell.py https://target
#   wp2shell.py host1 host2 ...
#   wp2shell.py -f hosts.txt [-j] [-t 20]
import sys, re, json, argparse
import concurrent.futures as cf
from urllib import request, error

UA = "wp2shell-check/1.0"
TIMEOUT = 15

def http(url, method="GET", data=None):
    headers = {"User-Agent": UA}
    if data:
        headers["Content-Type"] = "application/json"
    req = request.Request(url, method=method, data=data, headers=headers)
    try:
        with request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, r.read(100000).decode("utf-8", "replace")
    except error.HTTPError as e:
        body = e.read(100000).decode("utf-8", "replace") if e.fp else ""
        return e.code, body
    except Exception:
        return None, None

def affected(ver):
    if not ver:
        return None
    p = [int(x) for x in re.findall(r"\d+", ver)[:3]]
    while len(p) < 3:
        p.append(0)
    t = tuple(p)
    if (6, 9, 0) <= t < (6, 9, 5) or (7, 0, 0) <= t < (7, 0, 2):
        return "RCE"
    if (6, 8, 0) <= t < (6, 8, 6):
        return "SQLi"
    return None

def check(host):
    base = (host if "://" in host else "https://" + host).rstrip("/")
    status, body = http(base + "/")
    if status is None:
        return {"host": host, "verdict": "unreachable"}
    m = re.search(r'name="generator" content="WordPress ([0-9.]+)"', body or "")
    ver = m.group(1) if m else None
    _, batch = http(base + "/?rest_route=/batch/v1", "POST", b"{}")
    route = bool(batch) and ("rest_missing_callback_param" in batch or "rest_invalid_param" in batch)
    sev = affected(ver)
    if sev and route:
        verdict = f"VULNERABLE ({sev})"
    elif sev:
        verdict = f"version-affected ({sev}), route unconfirmed"
    elif ver:
        verdict = "not affected"
    else:
        verdict = "wordpress not detected"
    return {"host": host, "version": ver, "batch_route": route, "verdict": verdict}

def main():
    ap = argparse.ArgumentParser(description="wp2shell exposure check")
    ap.add_argument("hosts", nargs="*")
    ap.add_argument("-f", "--file", help="file with one host per line")
    ap.add_argument("-j", "--json", action="store_true")
    ap.add_argument("-t", "--threads", type=int, default=10)
    a = ap.parse_args()

    targets = list(a.hosts)
    if a.file:
        with open(a.file) as f:
            targets += [l.strip() for l in f if l.strip() and not l.startswith("#")]
    if not targets:
        ap.error("provide one or more hosts, or -f hosts.txt")

    with cf.ThreadPoolExecutor(max_workers=a.threads) as ex:
        results = list(ex.map(check, targets))

    if a.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            ver = f"  [{r['version']}]" if r.get("version") else ""
            print(f"{r['host']:<40} {r['verdict']}{ver}")

if __name__ == "__main__":
    main()
