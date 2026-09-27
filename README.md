# PhishDec — Phishing Domain Generator & Quishing Scanner

Defensive tool to find look-alike domains targeting your brand and scan QR codes for quishing.

Given `example.com`, PhishDec generates typosquat variants, checks which are registered (DNS + WHOIS + crt.sh), scores them 0–100 (`CLEAR` to `CRITICAL`), and exports HTML/JSON/CSV.

> For blue teams / SOC / brand protection. Use defensively (monitor, takedown, block, educate).

## Features

- **Generator** (`generator.py`): omission, transposition, duplication, insertion, keyboard-typo, ASCII/Unicode homoglyphs, bitsquat, hyphenation, dot-split, vowel-swap, pluralisation, prefix/suffix, TLD-swap. Each variant is labelled with its technique.
- **Checker** (`checker.py`): DNS + WHOIS + Certificate Transparency. Bulk mode DNS-scans everything first, then deep-checks only hits (or all if batch ≤ 60).
- **Scoring** (`enrich.py`): 0–100 risk score. +35 for edit-distance 1, +20 if registered, +20 for punycode/unicode, +15 for keywords/high-abuse TLD/homoglyph, +10 for keyboard/TLD-swap.
- **Quishing** (`quishing.py`): decode QRs (pyzbar → OpenCV), analyse URLs (IP host, `@` trick, shortener, brand typosquat), generate training QR kits.
- **Reports** (`reporter.py`): searchable HTML + JSON (full evidence) + CSV.
- **Watch** (`watcher.py`): poll variant set, alert on newly registered domains.

```
phishdec/
├── phishdec/generator.py  # variant generation
├── phishdec/checker.py    # DNS / WHOIS / CT
├── phishdec/enrich.py     # scoring + URL analysis
├── phishdec/quishing.py   # QR scan + kit
├── phishdec/reporter.py   # JSON / CSV / HTML
├── phishdec/watcher.py    # monitor loop
└── phishdec/cli.py        # CLI
```

## Install

Python 3.10+. Windows + Linux.

```powershell
cd phishdec
python -m venv .venv
.venv\Scripts\Activate.ps1   # Windows
# source .venv/bin/activate  # Linux
pip install -r requirements.txt
python -m phishdec.cli --help
```

Deps: `requests` (required), `dnspython` + `python-whois` (recommended), `opencv-python` + `pillow` (QR scan), `qrcode[pil]` (QR generation). Minimal install works with just `requests` — other steps report `skipped` instead of crashing.

## Usage

```powershell
# Offline variant generation
python -m phishdec.cli generate example.com --max 500

# Full sweep: generate + check + score + report
python -m phishdec.cli full example.com --max 1000 --report mybrand_report

# Check your own list
python -m phishdec.cli check examp1e.com evil.xyz --legit example.com --file suspects.txt

# Scan a QR code
python -m phishdec.cli scan-qr --image suspicious.png --legit example.com
python -m phishdec.cli scan-qr --text "http://example.com@evil.example/login"

# Make test QRs / training kit
python -m phishdec.cli make-qr --url "https://example.com/login" --out test.png
python -m phishdec.cli make-qr --kit example.com --out awareness_kit

# Monitor for new registrations
python -m phishdec.cli watch example.com --interval 3600 --high-only
```

Useful flags: `--unicode` (IDN homoglyphs), `--no-tld` (skip TLD swaps), `--no-whois --no-ct` (fast DNS-only), `--workers 20`, `--top 30`, `--formats json,html,csv`.

## Python API

```python
from phishdec import generate_variants, check_bulk, enrich_results
from phishdec.reporter import save_report

variants = generate_variants("example.com", max_variants=1000)
checks = check_bulk(variants, do_whois=True, do_ct=True)
ranked = enrich_results(variants, checks, legit="example.com")
save_report(ranked, "phishdec_report", formats=("json", "html", "csv"), legit="example.com")
```

## Notes

- WHOIS/CT/DNS data is best-effort: absence of evidence ≠ safe. Prioritise registered + `HIGH/CRITICAL` + has-MX rows first.
- Keep `watch --interval` ≥ 300s, don't hammer WHOIS/crt.sh.
- Only scan brands you own or are authorised to protect. Training QRs are for labelled exercises only.
