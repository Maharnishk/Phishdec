"""Domain intelligence enrichment + risk scoring (0-100)."""
from __future__ import annotations

import math
import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "secure", "login", "verify", "account", "update", "confirm", "signin",
    "bank", "wallet", "crypto", "free", "bonus", "prize", "support",
    "admin", "pay", "billing",
]

RISKY_TLDS = {"zip", "mov", "tk", "ml", "ga", "cf", "gq", "xyz", "top",
              "buzz", "country", "kim", "work", "click", "link", "lol"}

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
              "buff.ly", "adf.ly", "shorte.st"}


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[-1] + 1,
                           prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    c = Counter(s)
    return -sum((v / len(s)) * math.log2(v / len(s)) for v in c.values())


def score_domain(variant: str, legit: str, check: dict | None = None) -> dict:
    """Score a candidate variant against the legitimate domain."""
    check = check or {}
    v = variant.lower().strip().rstrip(".")
    legit = legit.lower().strip().rstrip(".")
    v_host = v.split("://")[-1].split("/")[0].split(":")[0].split("?")[0]
    l_host = legit.split("://")[-1].split("/")[0]
    v_sld, _, v_tld = v_host.rpartition(".")
    v_sld = v_sld.split(".")[-1] if "." in v_sld else v_sld
    l_sld, _, l_tld = l_host.rpartition(".")

    score = 0
    reasons: list[str] = []

    dist = levenshtein(v_sld, l_sld)
    if dist == 1:
        score += 35
        reasons.append(f"edit-distance=1 from '{l_sld}' (+35)")
    elif dist == 2:
        score += 25
        reasons.append(f"edit-distance=2 from '{l_sld}' (+25)")
    elif v_sld == l_sld and v_tld != l_tld:
        score += 25
        reasons.append(f"same SLD, different TLD .{v_tld} (+25)")

    tech_bonus = {"homoglyph-unicode": 20, "homoglyph-ascii": 15,
                  "bitsquat": 15, "keyboard-sub": 10, "tld-swap": 10}
    # technique passed via check dict optionally
    tech = (check.get("technique") or "")
    if tech in tech_bonus:
        score += tech_bonus[tech]
        reasons.append(f"technique {tech} (+{tech_bonus[tech]})")

    if any(k in v_sld for k in SUSPICIOUS_KEYWORDS):
        score += 15
        reasons.append("suspicious keyword in label (+15)")
    if v_tld in RISKY_TLDS:
        score += 15
        reasons.append(f"high-abuse TLD .{v_tld} (+15)")
    if v_host.startswith("xn--") or "xn--" in v_host:
        score += 20
        reasons.append("punycode/IDN homograph (+20)")
    if any(ord(c) > 127 for c in v):
        score += 20
        reasons.append("non-ASCII homoglyph chars (+20)")
    if "-" in v_sld:
        score += 5
        reasons.append("hyphen in label (+5)")
    if sum(c.isdigit() for c in v_sld) >= 2:
        score += 5
        reasons.append("multiple digits (+5)")
    ent = shannon_entropy(v_sld)
    if ent > 3.5:
        score += 5
        reasons.append(f"high entropy {ent:.1f} (+5)")

    reg = check.get("registered", False)
    if reg:
        score += 20
        reasons.append("domain is REGISTERED (+20)")
        dns = (check.get("dns") or {})
        if dns.get("mx"):
            score += 5
            reasons.append("has MX (can receive mail) (+5)")

    score = max(0, min(100, score))
    verdict = ("CRITICAL" if score >= 75 else "HIGH" if score >= 50
               else "MEDIUM" if score >= 30 else "LOW" if score >= 10 else "CLEAR")
    return {"domain": variant, "score": score, "verdict": verdict,
            "reasons": reasons, "distance": dist, "entropy": round(ent, 2),
            "registered": bool(reg)}


def enrich_results(variants: list[dict], checks: list[dict],
                   legit: str) -> list[dict]:
    """Merge generator output + checker output + scores, sorted by risk."""
    by_domain = {c["domain"]: c for c in checks}
    enriched = []
    for v in variants:
        dom = v["variant"]
        c = dict(by_domain.get(dom, {"domain": dom, "registered": False}))
        c["technique"] = v.get("technique", "")
        s = score_domain(dom, legit, c)
        enriched.append({
            "domain": dom,
            "technique": v.get("technique", ""),
            "registered": c.get("registered", False),
            "reasons_reg": c.get("registered_reasons", []),
            "score": s["score"],
            "verdict": s["verdict"],
            "risk_reasons": s["reasons"],
            "distance": s["distance"],
            "entropy": s["entropy"],
            "dns": c.get("dns", {}),
            "whois": c.get("whois", {}),
            "ct": c.get("ct", {}),
        })
    enriched.sort(key=lambda r: (-r["score"], r["domain"]))
    return enriched


# --- URL analysis shared with QR module --------------------------------------

def analyze_url(url: str, legit_domains: list[str] | None = None) -> dict:
    """Heuristic analysis of any URL (used by quishing scanner + reports)."""
    legit_domains = [d.lower().rstrip(".") for d in (legit_domains or [])]
    raw = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "http://" + raw
    try:
        p = urlparse(raw)
    except Exception:
        return {"url": url, "score": 50, "verdict": "MEDIUM",
                "flags": ["unparseable URL"], "host": ""}
    host = (p.hostname or "").lower().rstrip(".")
    flags: list[str] = []
    score = 0

    if p.scheme == "http":
        score += 10
        flags.append("plain HTTP (no TLS) (+10)")
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        score += 25
        flags.append("host is raw IP (+25)")
    if "@" in (p.netloc or ""):
        score += 25
        flags.append("'@' trick — userinfo disguises real host (+25)")
    if "xn--" in host or any(ord(c) > 127 for c in host):
        score += 20
        flags.append("punycode/unicode host (+20)")
    if host in SHORTENERS:
        score += 15
        flags.append("known URL shortener — hides destination (+15)")
    if p.port and p.port not in (80, 443):
        score += 10
        flags.append(f"non-standard port {p.port} (+10)")
    if host.count(".") >= 3:
        score += 10
        flags.append("deep subdomain chain (+10)")
    if len(raw) > 120:
        score += 5
        flags.append("very long URL (+5)")
    if re.search(r"(login|verify|secure|account|update|confirm|free|bonus)", raw.lower()):
        score += 10
        flags.append("phishy keywords in URL (+10)")
    if re.search(r"(token|redirect|url=|next=|goto=)", raw.lower()):
        score += 5
        flags.append("open-redirect param (+5)")

    for legit in legit_domains:
        lsld = legit.split(".")[0]
        hsld = host.split(".")[0] if "." in host else host
        d = levenshtein(hsld, lsld)
        if host != legit and (d <= 2 or (hsld == lsld and host != legit)):
            score += 30
            flags.append(f"looks like typosquat of {legit} (dist={d}) (+30)")
            break
        if legit in host and host != legit:
            score += 15
            flags.append(f"contains brand '{legit}' as substring (+15)")
            break

    score = max(0, min(100, score))
    verdict = ("CRITICAL" if score >= 75 else "HIGH" if score >= 50
               else "MEDIUM" if score >= 30 else "LOW" if score >= 10 else "CLEAR")
    return {"url": url, "normalised": raw, "host": host, "scheme": p.scheme,
            "score": score, "verdict": verdict, "flags": flags}
