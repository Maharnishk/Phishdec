"""CLI: generate / check / full / scan-qr / make-qr / watch."""
from __future__ import annotations

import argparse
import json
import sys

from .generator import TyposquatGenerator
from .checker import check_bulk
from .enrich import enrich_results
from .reporter import save_report


def _common_gen(p):
    p.add_argument("domain", help="Legitimate domain, e.g. example.com")
    p.add_argument("--unicode", action="store_true", help="Include unicode homoglyphs (IDN)")
    p.add_argument("--no-tld", action="store_true", help="Skip TLD swaps")
    p.add_argument("--max", type=int, default=2000, help="Max SLD variants (default 2000)")


def cmd_generate(a):
    gen = TyposquatGenerator(include_unicode=a.unicode,
                             include_tld=not a.no_tld, max_variants=a.max)
    variants = gen.generate(a.domain)
    if a.out == "json" or a.report:
        print(json.dumps(variants, indent=2))
    else:
        for v in variants:
            print(f"{v['variant']}\t{v['technique']}")
    print(f"\n# {len(variants)} variants", file=sys.stderr)
    if a.report:
        # bare variant list saved as json already printed; also save file
        with open(a.report, "w", encoding="utf-8") as f:
            json.dump(variants, f, indent=2)
        print(f"[saved {a.report}]", file=sys.stderr)


def cmd_check(a):
    domains = []
    if a.file:
        with open(a.file, encoding="utf-8") as f:
            domains += [l.strip() for l in f if l.strip()]
    if a.domains:
        domains += a.domains
    if not domains:
        print("Provide domains or --file", file=sys.stderr)
        sys.exit(2)
    # wrap as variant dicts so enrichment keeps technique if given
    variants = [{"variant": d, "technique": "direct"} for d in domains]
    checks = check_bulk(variants, max_workers=a.workers,
                        do_whois=not a.no_whois, do_ct=not a.no_ct,
                        progress=True)
    enriched = enrich_results(variants, checks, a.legit or "")
    for r in enriched:
        flag = "REGISTERED" if r["registered"] else "available"
        print(f"{r['domain']}\t{flag}\tscore={r['score']}\t{r['verdict']}")
    if a.report:
        paths = save_report(enriched, a.report,
                            formats=tuple(a.formats.split(",")),
                            legit=a.legit or "")
        print(f"[saved {', '.join(paths)}]", file=sys.stderr)


def cmd_full(a):
    gen = TyposquatGenerator(include_unicode=a.unicode,
                             include_tld=not a.no_tld, max_variants=a.max)
    print(f"[*] generating variants for {a.domain} …", file=sys.stderr)
    variants = gen.generate(a.domain)
    print(f"[*] {len(variants)} variants — checking DNS"
          f"{'' if a.no_whois else '+WHOIS'}{'' if a.no_ct else '+CT'} …",
          file=sys.stderr)
    checks = check_bulk(variants, max_workers=a.workers,
                        do_whois=not a.no_whois, do_ct=not a.no_ct,
                        progress=True)
    enriched = enrich_results(variants, checks, a.domain)
    reg = [r for r in enriched if r["registered"]]
    print(f"[*] {len(reg)} registered / {len(enriched)} total",
          file=sys.stderr)
    for r in enriched[: a.top]:
        print(f"{r['domain']}\t{r['technique']}\t"
              f"{'REG' if r['registered'] else '---'}\t"
              f"{r['score']}\t{r['verdict']}")
    paths = save_report(enriched, a.report,
                        formats=tuple(a.formats.split(",")), legit=a.domain)
    print(f"[saved {', '.join(paths)}]", file=sys.stderr)


def cmd_scan_qr(a):
    from .quishing import scan_qr_image, scan_qr_text
    legit = a.legit.split(",") if a.legit else []
    if a.text:
        res = scan_qr_text(a.text, legit)
        print(json.dumps(res, indent=2))
        return
    from .quishing import decode_qr
    from .enrich import analyze_url
    payloads = decode_qr(a.image)
    if not payloads:
        print("No QR code found in image.")
        return
    for p in payloads:
        res = analyze_url(p, legit)
        print(f"payload: {p}\n  -> {res['verdict']} ({res['score']})")
        for fl in res["flags"]:
            print(f"     - {fl}")


def cmd_make_qr(a):
    from .quishing import generate_awareness_kit, generate_test_qr
    if a.kit:
        manifest = generate_awareness_kit(a.kit, a.out)
        print(json.dumps(manifest, indent=2))
        print(f"[kit written to {a.out}/]", file=sys.stderr)
    else:
        fp = generate_test_qr(a.url, a.out)
        print(f"[QR written to {fp}]")


def cmd_watch(a):
    from .watcher import watch
    watch(a.domain, interval=a.interval, max_variants=a.max,
          include_unicode=a.unicode, max_workers=a.workers,
          iterations=a.iterations, alert_high_only=a.high_only)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="phishdec",
                                description="Phishing Domain Generator & Quishing Scanner")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="Generate typosquat variants")
    _common_gen(g)
    g.add_argument("--out", choices=["text", "json"], default="text")
    g.add_argument("--report", default=None, help="Save JSON to file")
    g.set_defaults(func=cmd_generate)

    c = sub.add_parser("check", help="Check registration + score domains")
    c.add_argument("domains", nargs="*", help="Domains to check")
    c.add_argument("--file", default=None, help="File with one domain per line")
    c.add_argument("--legit", default="", help="Legit brand domain for scoring context")
    c.add_argument("--workers", type=int, default=20)
    c.add_argument("--no-whois", action="store_true")
    c.add_argument("--no-ct", action="store_true")
    c.add_argument("--report", default="phishdec_report", help="Report basename")
    c.add_argument("--formats", default="json,html,csv")
    c.set_defaults(func=cmd_check)

    f = sub.add_parser("full", help="Generate + check + score + report")
    _common_gen(f)
    f.add_argument("--workers", type=int, default=20)
    f.add_argument("--no-whois", action="store_true")
    f.add_argument("--no-ct", action="store_true")
    f.add_argument("--top", type=int, default=30, help="Show top N rows")
    f.add_argument("--report", default="phishdec_report")
    f.add_argument("--formats", default="json,html,csv")
    f.set_defaults(func=cmd_full)

    s = sub.add_parser("scan-qr", help="Decode + analyse a QR code")
    s.add_argument("--image", default=None, help="Image file containing QR")
    s.add_argument("--text", default=None, help="QR payload text directly")
    s.add_argument("--legit", default="", help="Comma-separated brand domains")
    s.set_defaults(func=cmd_scan_qr)

    m = sub.add_parser("make-qr", help="Generate test QRs for awareness training")
    m.add_argument("--url", default=None, help="URL to encode")
    m.add_argument("--kit", default=None, help="Legit domain to build awareness kit for")
    m.add_argument("--out", default="qr_out.png", help="Output file (or dir for --kit)")
    m.set_defaults(func=cmd_make_qr)

    w = sub.add_parser("watch", help="Continuously monitor for new registrations")
    _common_gen(w)
    w.add_argument("--interval", type=int, default=3600)
    w.add_argument("--workers", type=int, default=20)
    w.add_argument("--iterations", type=int, default=None)
    w.add_argument("--high-only", action="store_true")
    w.set_defaults(func=cmd_watch)
    return p


def main(argv=None):
    p = build_parser()
    a = p.parse_args(argv)
    a.func(a)


if __name__ == "__main__":
    main()
