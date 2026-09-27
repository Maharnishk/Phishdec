"""Watch mode: continuous monitoring for newly-registered squats."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from .generator import TyposquatGenerator
from .checker import check_bulk
from .enrich import enrich_results


def watch(domain: str, interval: int = 3600, max_variants: int = 2000,
          include_unicode: bool = False, max_workers: int = 20,
          iterations: int | None = None, alert_high_only: bool = False,
          report_prefix: str = "watch") -> None:
    """Poll typosquat space; alert when a new registered domain appears.

    interval: seconds between rounds. iterations: None = forever.
    """
    gen = TyposquatGenerator(include_unicode=include_unicode,
                             max_variants=max_variants)
    variants = gen.generate(domain)
    print(f"[watch] monitoring {len(variants)} variants of {domain} "
          f"every {interval}s (Ctrl+C to stop)")
    known_registered: set[str] | None = None
    round_no = 0
    try:
        while True:
            round_no += 1
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            print(f"\n[watch] round {round_no} @ {ts}")
            # light mode: DNS-only in watch loop (fast, polite)
            checks = check_bulk(variants, max_workers=max_workers,
                                do_whois=False, do_ct=False)
            enriched = enrich_results(variants, checks, domain)
            reg = {r["domain"] for r in enriched if r["registered"]}
            if alert_high_only:
                shown = [r for r in enriched
                         if r["registered"] and r["score"] >= 50]
            else:
                shown = [r for r in enriched if r["registered"]]

            if known_registered is None:
                print(f"[watch] baseline: {len(reg)} registered "
                      f"({len(shown)} shown)")
            else:
                new = reg - known_registered
                gone = known_registered - reg
                if new:
                    print(f"[watch] ALERT — {len(new)} NEWLY registered:")
                    for r in enriched:
                        if r["domain"] in new:
                            print(f"  + {r['domain']} [{r['technique']}] "
                                  f"score={r['score']} {r['verdict']}")
                else:
                    print("[watch] no new registrations.")
                if gone:
                    print(f"[watch] {len(gone)} no longer resolve: "
                          f"{sorted(gone)[:5]}")
            for r in (shown if known_registered is None else
                      [x for x in enriched if x["domain"] in (new if known_registered is not None else set())]):
                print(f"  {'*' if r['score'] >= 50 else '-'} {r['domain']} "
                      f"[{r['technique']}] score={r['score']} {r['verdict']}")

            known_registered = reg
            if iterations is not None and round_no >= iterations:
                print("[watch] iterations exhausted — exiting.")
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[watch] stopped by user.")
