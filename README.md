# PhishDec — Phishing Domain Generator & Quishing Scanner

Defensive tool to find **typosquat / look-alike domains** targeting your brand and to scan **QR codes for quishing** (QR phishing).

Given a legitimate domain like `example.com`, PhishDec:

1. **Generates** hundreds–thousands of attacker-plausible variants (omission, transposition, homoglyphs, bitsquatting, TLD swaps, etc.)
2. **Checks** which ones are actually registered (DNS + WHOIS + Certificate Transparency via crt.sh)
3. **Scores** each variant 0–100 with a `CLEAR / LOW / MEDIUM / HIGH / CRITICAL` verdict
4. **Reports** to searchable HTML + JSON + CSV
5. **Scans QR codes** for malicious URLs and can **generate a QR awareness training kit**
6. **Watches** your typosquat space continuously for new registrations

> Built for blue teams, SOC analysts, brand-protection teams, and security-awareness trainers. Offensive use (registering squats to phish) is out of scope — use defensively (monitor, takedown, block, educate).

---

## Features

### 1. Typosquat generator (`generator.py`)
13 technique families, all labelled per-variant:

| Technique | Example for `paypal.com` | Description |
|---|---|---|
| `omission` | `payal.com` | Drop one character |
| `transposition` | `papyla.com` | Swap two adjacent chars |
| `duplication` | `payypal.com` | Double a character |
| `insertion` | `payxpal.com` | Insert a-z, 0-9, `-` (capped at 1500) |
| `keyboard-sub` | `payoal.com` | QWERTY-adjacent key typo |
| `homoglyph-ascii` | `p4ypal.com`, `paypa1.com` | `a→4/@`, `o→0`, `l→1`, `m→rn`, etc. |
| `homoglyph-unicode` | `pаypal.com` (Cyrillic `а`) | IDN confusables, opt-in via `--unicode` |
| `bitsquat` | `qaypal.com` | Single-bit-flip of each char (DNS-valid only) |
| `hyphenation` | `pay-pal.com` | Insert `-`; also handles hyphen removal |
| `subdomain-dot` | `pay.pal.com` | Dot-split subdomain trick |
| `vowel-swap` | `peypal.com` | `a↔e↔i↔o↔u` |
| `pluralisation` | `paypals.com` | Add/strip trailing `s` |
| `prefix` / `suffix` | `secure-paypal.com`, `paypal-login.com` | `secure, login, verify, account, support, pay, app…` |
| `tld-swap` | `paypal.xyz`, `paypal.io` | 20+ common/high-abuse TLDs |

### 2. Registration checker (`checker.py`)
For each candidate FQDN:

- **DNS** — `socket.gethostbyname_ex` + optional `dnspython` A/MX/NS records
- **WHOIS** — `python-whois` registrar / creation / expiry / taken-vs-available
- **CT** — `crt.sh` certificate search (`?q=%.domain&output=json`)

`registered = dns-resolves OR whois-taken OR ct-cert-found`

`check_bulk()` uses a polite two-phase strategy: DNS-scan everything concurrently, then run slow WHOIS/CT lookups **only on DNS-positive hosts** (or on all hosts if batch ≤ 60).

### 3. Risk scoring (`enrich.py`)
`score_domain(variant, legit)` → 0–100 + verdict:

| Signal | Points |
|---|---|
| Levenshtein distance 1 from brand SLD | +35 |
| Distance 2 / same SLD different TLD | +25 |
| Unicode homoglyph / punycode (`xn--`) | +20 |
| ASCII homoglyph / bitsquat | +15/+15 |
| Suspicious keyword (`login, verify, secure, bank…`) | +15 |
| High-abuse TLD (`.zip, .mov, .tk, .xyz, .top…`) | +15 |
| Keyboard-sub / TLD-swap technique | +10 |
| Domain is REGISTERED | +20 (+5 more if it has MX — can receive mail) |
| Hyphen, digits, high entropy | +5 each |

Verdicts: `≥75 CRITICAL`, `≥50 HIGH`, `≥30 MEDIUM`, `≥10 LOW`, else `CLEAR`.

`analyze_url()` applies a parallel heuristic set to full URLs (raw-IP host, `@` trick, shortener, non-standard port, deep subdomains, open-redirect params, brand-substring/typosquat match).

### 4. Quishing scanner (`quishing.py`)
- `decode_qr(image)` — tries `pyzbar` first, falls back to `opencv-python` `QRCodeDetector` (multi + single)
- `scan_qr_image()` / `scan_qr_text()` — decode + `analyze_url()` each payload
- `generate_test_qr()` / `generate_awareness_kit()` — build labelled demo QRs for training

### 5. Reporting (`reporter.py`)
`save_report(results, basename, formats, legit)` writes:

- `.json` — full evidence (DNS/WHOIS/CT + scores + reasons)
- `.csv` — `domain, technique, registered, score, verdict, distance, entropy, risk_reasons, registered_reasons`
- `.html` — self-contained dark-theme page with verdict badges + live filter box, registered rows highlighted

### 6. Watch mode (`watcher.py`)
Polls the full variant set on an interval (default 3600s), diffs the registered set each round, and prints `ALERT — NEWLY registered` lines. DNS-only in the loop for speed/politeness.

---

## Project structure

```
phishdec/
├── phishdec/
│   ├── __init__.py    # public API: generate_variants, score_domain, check_domain…
│   ├── generator.py   # TyposquatGenerator + technique tables
│   ├── checker.py     # DNS + WHOIS + crt.sh CT lookups, check_bulk()
│   ├── enrich.py      # 0-100 scoring, analyze_url()
│   ├── quishing.py    # QR decode / scan / awareness-kit generation
│   ├── reporter.py    # JSON / CSV / HTML reports
│   ├── watcher.py     # continuous monitoring loop
│   └── cli.py         # argparse CLI (generate/check/full/scan-qr/make-qr/watch)
├── examples/          # (empty — put sample reports / QR images here)
├── requirements.txt
└── README.md
```

---

## Installation

Requirements: **Python 3.10+**. Tested on Windows + Linux.

```powershell
# 1. Clone / enter project
cd phishdec

# 2. (Recommended) virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1        # Windows PowerShell
# source .venv/bin/activate       # Linux / macOS

# 3. Install dependencies
pip install -r requirements.txt

# 4. Verify
python -m phishdec.cli --help
```

`requirements.txt` breakdown:

```
requests>=2.31          # CT (crt.sh) lookups — required
dnspython>=2.4          # rich DNS records — highly recommended
python-whois>=0.9       # WHOIS enrichment — highly recommended
opencv-python>=4.8      # QR decode without system DLLs — for scan-qr
pillow>=10.0            # image handling for QR
pyzbar>=0.1.9           # more accurate QR decode (non-Windows only; needs zbar system lib)
qrcode[pil]>=7.4        # QR generation for awareness kit
```

> Minimal install works with just `requests` — DNS falls back to stdlib `socket`, WHOIS/QR steps report `skipped`/`missing` errors instead of crashing. On Windows skip `pyzbar` (OpenCV path is used).

---

## Quick start

```powershell
# Generate variants only (no network)
python -m phishdec.cli generate example.com --max 500

# Full pipeline: generate + check + score + HTML/JSON/CSV report
python -m phishdec.cli full example.com --max 1000 --report mybrand_report

# Check a custom list against your brand
python -m phishdec.cli check paypa1.com secure-paypal.xyz --legit paypal.com

# Scan a QR code image
python -m phishdec.cli scan-qr --image suspicious.png --legit paypal.com

# Build a 10-QR awareness training kit
python -m phishdec.cli make-qr --kit example.com --out awareness_kit

# Monitor continuously (hourly by default)
python -m phishdec.cli watch example.com --interval 3600
```

---

## CLI reference

All commands: `python -m phishdec.cli <command> --help`

### `generate` — variant enumeration (offline)

```powershell
python -m phishdec.cli generate paypal.com --max 2000 --out text
python -m phishdec.cli generate paypal.com --unicode --no-tld --max 500 --out json --report variants.json
```

| Flag | Default | Meaning |
|---|---|---|
| `domain` | (required) | Legit domain, e.g. `example.com` |
| `--unicode` | off | Include Unicode/IDN homoglyphs (Cyrillic, Greek, accented) |
| `--no-tld` | off | Skip TLD swaps |
| `--max` | 2000 | Max SLD variants (insertion capped internally at 1500) |
| `--out` | `text` | `text` (`variant<TAB>technique`) or `json` |
| `--report` | none | Save JSON variant list to file |

### `check` — score existing domains (online)

```powershell
python -m phishdec.cli check examp1e.com secure-example.xyz --legit example.com
python -m phishdec.cli check --file suspects.txt --legit example.com --report check_report --formats json,html,csv
python -m phishdec.cli check evil.com --legit example.com --no-whois --no-ct --workers 10
```

| Flag | Default | Meaning |
|---|---|---|
| `domains` | — | One or more domains on the command line |
| `--file` | — | File with one domain per line (combined with CLI domains) |
| `--legit` | `""` | Brand domain for scoring context (strongly recommended) |
| `--workers` | 20 | DNS threads (deep WHOIS/CT phase capped at 10) |
| `--no-whois` / `--no-ct` | off | Skip WHOIS / crt.sh lookups (faster, DNS-only + scoring) |
| `--report` | `phishdec_report` | Report basename (extensions added automatically) |
| `--formats` | `json,html,csv` | Comma-separated subset to write |

Output line per domain: `domain<TAB>REGISTERED|available<TAB>score=N<TAB>VERDICT`.

### `full` — end-to-end brand sweep (online, most common)

```powershell
python -m phishdec.cli full example.com --max 2000 --top 30 --report phishdec_report --formats json,html,csv
python -m phishdec.cli full example.com --unicode --workers 30 --no-whois
```

Same generator flags as `generate` plus checker flags (`--workers`, `--no-whois`, `--no-ct`) plus:

| Flag | Default | Meaning |
|---|---|---|
| `--top` | 30 | Print top-N highest-scoring rows to console (full set still saved) |
| `--report` | `phishdec_report` | Basename for `.json` / `.html` / `.csv` |
| `--formats` | `json,html,csv` | Which reports to write |

Typical run prints progress to stderr (`[*] generating…`, `[dns] 50/1200…`, `[*] N registered / M total`) and saves e.g. `phishdec_report.json/.html/.csv`. Open the HTML in a browser, filter by verdict/technique, and pivot on registered `HIGH`/`CRITICAL` rows first.

### `scan-qr` — quishing analysis

```powershell
python -m phishdec.cli scan-qr --image qr.png --legit paypal.com,example.com
python -m phishdec.cli scan-qr --text "http://example.com@evil.example/login"
```

- `--image` — decode with pyzbar → OpenCV, then `analyze_url()` each payload (flags + score + verdict printed)
- `--text` — analyse a payload string directly (e.g. pasted from a phone scan), JSON output
- `--legit` — comma-separated brand domains for typosquat comparison

### `make-qr` — awareness / test QRs

```powershell
python -m phishdec.cli make-qr --url "https://example.com/login" --out test.png
python -m phishdec.cli make-qr --kit example.com --out awareness_kit
```

- Without `--kit`: encode one URL to a PNG.
- With `--kit <legit>`: generate 10 labelled QRs in `--out` dir covering legit, letter-swap, homoglyph-zero, wrong-TLD, shortener, IP host, `@` trick, punycode, subdomain spoof, HTTP downgrade — plus a JSON manifest with `expected` verdicts for classroom use.

### `watch` — continuous monitoring

```powershell
python -m phishdec.cli watch example.com --interval 3600 --max 2000
python -m phishdec.cli watch example.com --interval 300 --iterations 5 --high-only --workers 20
```

| Flag | Default | Meaning |
|---|---|---|
| `--interval` | 3600 | Seconds between rounds |
| `--iterations` | forever | Stop after N rounds (useful for cron/CI) |
| `--high-only` | off | Only display registered domains with score ≥ 50 |
| `--unicode` / `--max` / `--workers` | — | Same as generator/checker |

First round establishes the baseline; subsequent rounds diff and alert on `+ NEWLY registered` and list names that stopped resolving. Uses DNS-only checks in the loop. Stop with `Ctrl+C`.

---

## Python API

```python
from phishdec import generate_variants, check_bulk, enrich_results, score_domain
from phishdec.quishing import scan_qr_image, scan_qr_text, generate_awareness_kit
from phishdec.reporter import save_report

# 1. Generate
variants = generate_variants("example.com", include_unicode=False, max_variants=1000)
print(variants[0])  # {'variant': 'exaple.com', 'technique': 'omission', ...}

# 2. Check registration (DNS + WHOIS + CT)
checks = check_bulk(variants, max_workers=20, do_whois=True, do_ct=True, progress=True)

# 3. Score + sort by risk
ranked = enrich_results(variants, checks, legit="example.com")
for r in ranked[:5]:
    print(r["domain"], r["technique"], r["registered"], r["score"], r["verdict"])

# 4. Report
save_report(ranked, "phishdec_report", formats=("json", "html", "csv"), legit="example.com")

# Single-domain scoring without network
print(score_domain("examp1e.com", "example.com"))

# QR workflows
print(scan_qr_text("http://example.com@evil.example/login", ["example.com"]))
print(scan_qr_image("suspicious.png", ["example.com"]))
generate_awareness_kit("example.com", outdir="awareness_kit")
```

---

## Example session

```powershell
> python -m phishdec.cli full paypal.com --max 500 --top 5 --formats json,html,csv
[*] generating variants for paypal.com …
[*] 523 variants — checking DNS+WHOIS+CT …
  [dns] 50/523...
  [dns] 100/523...
[*] 41 registered / 523 total
paypal.xyz            tld-swap        REG     60      HIGH
pay-pal.com           hyphenation     REG     60      HIGH
paypals.com           pluralisation   REG     60      HIGH
secure-paypal.com     prefix          REG     55      HIGH
paypa1.com            homoglyph-ascii REG     70      HIGH
[saved phishdec_report.json, phishdec_report.html, phishdec_report.csv]
```

Open `phishdec_report.html` → filter `HIGH` → investigate registered rows → submit takedowns / add to blocklists / create detection rules.

---

## Operational tips

- **Start small**: `--max 300–500` for a first run; scale to 2000+ once you know timing. WHOIS + crt.sh are rate-limited — large `full` sweeps take minutes.
- **Fast triage**: `--no-whois --no-ct` gives DNS-only results in seconds; re-run deep checks on the registered subset.
- **Prioritise**: registered + `CRITICAL/HIGH` + has-MX (can send/receive mail) + young WHOIS creation date = investigate first.
- **Reduce noise**: batches > 60 only deep-check DNS-positive hosts by design (see `checker.check_bulk`). Batches ≤ 60 always deep-check everything.
- **Be polite**: default 20 DNS workers is reasonable; don't hammer WHOIS/crt.sh in tight `watch` loops — keep `--interval` ≥ 300s.
- **QR**: prefer `pyzbar` accuracy on Linux; on Windows rely on OpenCV. Blurry/rotated photos decode worse — try `--text` mode with the phone-scanned payload as fallback.

---

## Limitations

- WHOIS data is inconsistent across registrars/TLDs (`available: None` means inconclusive, not available).
- crt.sh only sees hosts that obtained public certs — absence proves nothing.
- DNS resolution depends on your resolver; parked/sinkholed domains still show as registered.
- Unicode mode uses a small curated confusable set — a full UTS-39 set would explode combinatorially.
- No RDAP, no screenshot/content analysis, no registrar-API takedown automation (JSON/CSV exports are meant to feed those workflows).

---

## Responsible use

This is a **defensive** tool. Only scan brands you own or are authorised to protect. Do not register squats to impersonate others, do not embed malicious QRs in real campaigns, and use generated awareness QRs only in labelled training environments.

---
