"""Registration checker: DNS + WHOIS + Certificate-Transparency lookups."""
from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import dns.resolver  # type: ignore
    _HAS_DNSPYTHON = True
except Exception:
    _HAS_DNSPYTHON = False

try:
    import whois as _whois_lib  # python-whois
    _HAS_WHOIS = True
except Exception:
    _HAS_WHOIS = False
    _whois_lib = None

try:
    import requests
    _HAS_REQUESTS = True
except Exception:
    _HAS_REQUESTS = False
    requests = None  # type: ignore


def _dns_lookup(host: str, timeout: float = 4.0) -> dict:
    """Resolve A/MX/NS. Returns dict with ips and flags."""
    info: dict = {"resolves": False, "ips": [], "mx": [], "ns": [],
                  "method": "socket", "error": None}
    # 1) fast socket check
    try:
        socket.setdefaulttimeout(timeout)
        _, _, ips = socket.gethostbyname_ex(host)
        if ips:
            info["resolves"] = True
            info["ips"] = ips
    except Exception as e:
        info["error"] = str(e)[:200]
    # 2) richer records via dnspython (optional)
    if _HAS_DNSPYTHON:
        try:
            res = dns.resolver.Resolver()
            res.lifetime = timeout
            res.timeout = timeout
            for rtype, key in (("A", "ips"), ("MX", "mx"), ("NS", "ns")):
                try:
                    ans = res.resolve(host, rtype)
                    vals = [str(r).strip() for r in ans]
                    if vals:
                        info[key] = sorted(set(info[key] | set(vals)) if key == "ips" else vals)
                        info["resolves"] = True
                    info["method"] = "socket+dnspython"
                except Exception:
                    continue
        except Exception:
            pass
    return info


def _whois_lookup(domain: str, timeout: float = 10.0) -> dict:
    out: dict = {"available": None, "registrar": None, "creation_date": None,
                 "expiration_date": None, "raw": None, "error": None}
    if not _HAS_WHOIS:
        out["error"] = "python-whois not installed (pip install python-whois)"
        return out
    try:
        socket.setdefaulttimeout(timeout)
        w = _whois_lib.whois(domain)  # type: ignore
        text = str(w.get("status") or w.text if hasattr(w, "text") else w)
        out["raw"] = (str(w)[:2000])
        # python-whois returns None-ish on unregistered
        domain_name = w.get("domain_name") if isinstance(w, dict) else getattr(w, "domain_name", None)
        if not domain_name:
            # heuristically unregistered
            out["available"] = True if ("No match" in text or "NOT FOUND" in text.upper()) else None
        else:
            out["available"] = False
        out["registrar"] = str(w.get("registrar")) if isinstance(w, dict) else str(getattr(w, "registrar", None))
        cd = w.get("creation_date") if isinstance(w, dict) else getattr(w, "creation_date", None)
        ed = w.get("expiration_date") if isinstance(w, dict) else getattr(w, "expiration_date", None)
        # normalise list -> first
        if isinstance(cd, list):
            cd = cd[0] if cd else None
        if isinstance(ed, list):
            ed = ed[0] if ed else None
        out["creation_date"] = str(cd) if cd else None
        out["expiration_date"] = str(ed) if ed else None
    except Exception as e:
        out["error"] = str(e)[:300]
    return out


def _ct_lookup(domain: str, timeout: float = 10.0) -> dict:
    """Query crt.sh for certs covering this exact name."""
    out: dict = {"found": False, "count": 0, "issuers": [], "error": None}
    if not _HAS_REQUESTS:
        out["error"] = "requests not installed"
        return out
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url, timeout=timeout, headers={"User-Agent": "phishdec/1.0"})
        if r.status_code != 200:
            # fallback: exact query
            url2 = f"https://crt.sh/?q={domain}&output=json"
            r = requests.get(url2, timeout=timeout, headers={"User-Agent": "phishdec/1.0"})
        if r.status_code == 200:
            try:
                data = r.json()
            except Exception:
                out["error"] = "crt.sh non-JSON response"
                return out
            exact = [e for e in data
                     if str(e.get("name_value", "")).lower().split("\n").__contains__(domain.lower())
                     or domain.lower() in str(e.get("name_value", "")).lower()]
            out["count"] = len(exact)
            out["found"] = len(exact) > 0
            issuers = sorted({str(e.get("issuer_name", ""))[:80] for e in exact if e.get("issuer_name")})
            out["issuers"] = issuers[:5]
        else:
            out["error"] = f"crt.sh HTTP {r.status_code}"
    except Exception as e:
        out["error"] = str(e)[:200]
    return out


def check_domain(domain: str, do_whois: bool = True, do_ct: bool = True,
                 timeout: float = 4.0) -> dict:
    """Full intelligence for one FQDN."""
    host = domain.strip().lower().rstrip(".")
    started = time.time()
    dns = _dns_lookup(host, timeout=timeout)
    who = _whois_lookup(host) if do_whois else {"available": None, "error": "skipped"}
    ct = _ct_lookup(host) if do_ct else {"found": False, "count": 0, "error": "skipped"}

    # registered heuristic: DNS resolves OR whois says taken OR CT has certs
    registered = False
    reasons = []
    if dns.get("resolves"):
        registered = True
        reasons.append("dns-resolves")
    if who.get("available") is False:
        registered = True
        reasons.append("whois-taken")
    if ct.get("found"):
        registered = True
        reasons.append("ct-cert")
    return {
        "domain": host,
        "registered": registered,
        "registered_reasons": reasons,
        "dns": dns,
        "whois": who,
        "ct": ct,
        "elapsed": round(time.time() - started, 2),
    }


def check_bulk(variants: list, max_workers: int = 20, do_whois: bool = True,
               do_ct: bool = True, timeout: float = 4.0,
               progress: bool = False) -> list[dict]:
    """Concurrently check a list of fqdn strings or {'variant':...} dicts."""
    domains = [v["variant"] if isinstance(v, dict) and "variant" in v else str(v)
               for v in variants]
    # WHOIS/CT are slow + rate-limited: only run them for DNS-positive hosts
    # unless the batch is small. Two-phase approach.
    results: dict[str, dict] = {}

    def _dns_only(d):
        return d, _dns_lookup(d, timeout=timeout)

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(_dns_only, d): d for d in domains}
        for i, fut in enumerate(as_completed(futs)):
            d, dns = fut.result()
            results[d] = {"domain": d, "dns": dns, "whois": {"available": None, "error": "pending"},
                          "ct": {"found": False, "count": 0, "error": "pending"},
                          "registered": bool(dns.get("resolves")),
                          "registered_reasons": ["dns-resolves"] if dns.get("resolves") else []}
            if progress and (i + 1) % 50 == 0:
                print(f"  [dns] {i + 1}/{len(domains)}...")

    # Phase 2: enrich only candidates (DNS-positive) + small batches fully
    needs_deep = [d for d, r in results.items() if r["registered"]] \
        if len(domains) > 60 else list(domains)

    def _deep(d):
        who = _whois_lookup(d) if do_whois else {"available": None, "error": "skipped"}
        ct = _ct_lookup(d) if do_ct else {"found": False, "count": 0, "error": "skipped"}
        return d, who, ct

    if needs_deep and (do_whois or do_ct):
        with ThreadPoolExecutor(max_workers=min(10, max_workers)) as ex:
            futs = {ex.submit(_deep, d): d for d in needs_deep}
            for fut in as_completed(futs):
                d, who, ct = fut.result()
                r = results[d]
                r["whois"], r["ct"] = who, ct
                if who.get("available") is False and "whois-taken" not in r["registered_reasons"]:
                    r["registered"] = True
                    r["registered_reasons"].append("whois-taken")
                if ct.get("found") and "ct-cert" not in r["registered_reasons"]:
                    r["registered"] = True
                    r["registered_reasons"].append("ct-cert")

    # preserve input order
    order = {d: i for i, d in enumerate(domains)}
    return [results[d] for d in sorted(results, key=lambda d: order[d])]
