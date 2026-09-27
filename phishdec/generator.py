"""Comprehensive typosquat variant generator.

Covers: omission, transposition, duplication, insertion, keyboard-adjacency
substitution, ASCII homoglyphs, Unicode homoglyphs, bitsquatting,
hyphenation, dot-splitting, vowel-swap, pluralisation, prefix/suffix
affixes, and TLD swaps.
"""
from __future__ import annotations

import itertools
import string

# --- static tables -----------------------------------------------------------

KEYBOARD_ADJACENCY = {
    "q": "wa", "w": "qae", "e": "wrs", "r": "etd", "t": "ryf", "y": "tug",
    "u": "yih", "i": "uoj", "o": "ipk", "p": "ol",
    "a": "qwsz", "s": "awedxz", "d": "serfcx", "f": "drtgvc", "g": "ftyhbv",
    "h": "gyujnb", "j": "huikmn", "k": "jiolm", "l": "kop",
    "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn",
    "n": "bhjm", "m": "njk",
    "0": "9", "1": "2", "2": "13", "3": "24", "4": "35", "5": "46",
    "6": "57", "7": "68", "8": "79", "9": "80",
}

# ASCII look-alikes (bidirectional where sensible)
HOMOGLYPH_ASCII = {
    "a": ["4", "@"],
    "b": ["6", "8"],
    "c": ["k", "s"],
    "d": ["cl"],
    "e": ["3"],
    "g": ["9", "6"],
    "h": ["n"],
    "i": ["1", "l", "!"],
    "j": ["i"],
    "k": ["c"],
    "l": ["1", "i"],
    "m": ["rn", "nn"],
    "n": ["h", "m"],
    "o": ["0"],
    "p": ["q"],
    "q": ["p", "9"],
    "r": ["n"],
    "s": ["5", "$", "z"],
    "t": ["7"],
    "u": ["v"],
    "v": ["u"],
    "w": ["vv"],
    "x": ["ks"],
    "y": ["j"],
    "z": ["2", "s"],
    "0": ["o"],
    "1": ["l", "i"],
    "2": ["z"],
    "3": ["e"],
    "4": ["a"],
    "5": ["s"],
    "6": ["b", "g"],
    "7": ["t"],
    "8": ["b"],
    "9": ["g", "q"],
}

# Small curated unicode confusables (single-char -> list).
# Kept small on purpose: full IDN confusable set would explode combinatorially.
HOMOGLYPH_UNICODE = {
    "a": ["\u00e0", "\u00e1", "\u00e2", "\u00e4", "\u0251"],
    "c": ["\u00e7", "\u0107"],
    "e": ["\u00e9", "\u00e8", "\u00ea", "\u00eb"],
    "i": ["\u00ed", "\u00ef", "\u0131"],
    "n": ["\u00f1"],
    "o": ["\u00f3", "\u00f6", "\u03bf"],  # last is Greek omicron
    "p": ["\u0440"],  # Cyrillic er
    "s": ["\u0455"],  # Cyrillic dze
    "u": ["\u00fa", "\u00fc"],
    "x": ["\u0445"],  # Cyrillic ha
    "y": ["\u00fd"],
}

COMMON_TLDS = [
    "com", "net", "org", "io", "co", "ai", "app", "dev", "info", "biz",
    "us", "uk", "in", "de", "xyz", "top", "site", "online", "shop",
    "net", "org", "edu", "gov",
]

VOWELS = "aeiou"

PREFIXES = ["secure", "login", "verify", "account", "support", "update", "my"]
SUFFIXES = ["secure", "login", "verify", "pay", "app", "web", "online", "hq"]


def split_domain(domain: str) -> tuple[str, str]:
    """Split 'example.com' -> ('example', 'com'). Handles multi-label TLDs naively."""
    domain = domain.strip().lower().rstrip(".")
    if "." not in domain:
        return domain, "com"
    sld, _, tld = domain.rpartition(".")
    sld = sld.split(".")[-1]  # keep only immediate label for mutation
    return sld, tld or "com"


def _add(store: dict, variant: str, technique: str, sld: str):
    if not variant or variant == sld:
        return
    # basic DNS label sanity: length, charset (allow unicode for homoglyph mode)
    if len(variant) > 63 or len(variant) == 0:
        return
    if variant.startswith("-") or variant.endswith("-"):
        return
    if variant not in store:
        store[variant] = technique


class TyposquatGenerator:
    def __init__(self, include_unicode: bool = False, include_tld: bool = True,
                 max_variants: int = 5000):
        self.include_unicode = include_unicode
        self.include_tld = include_tld
        self.max_variants = max_variants

    # -- individual techniques (each returns dict variant->technique) ---------
    def omission(self, sld: str) -> dict:
        out = {}
        for i in range(len(sld)):
            _add(out, sld[:i] + sld[i + 1:], "omission", sld)
        return out

    def transposition(self, sld: str) -> dict:
        out = {}
        for i in range(len(sld) - 1):
            v = sld[:i] + sld[i + 1] + sld[i] + sld[i + 2:]
            _add(out, v, "transposition", sld)
        return out

    def duplication(self, sld: str) -> dict:
        out = {}
        for i in range(len(sld)):
            _add(out, sld[:i + 1] + sld[i] + sld[i + 1:], "duplication", sld)
        return out

    def insertion(self, sld: str) -> dict:
        out = {}
        charset = string.ascii_lowercase + string.digits + "-"
        for i in range(len(sld) + 1):
            for ch in charset:
                _add(out, sld[:i] + ch + sld[i:], "insertion", sld)
                if len(out) > 1500:  # cap: insertion alone is huge
                    return out
        return out

    def keyboard_sub(self, sld: str) -> dict:
        out = {}
        for i, ch in enumerate(sld):
            for rep in KEYBOARD_ADJACENCY.get(ch, ""):
                _add(out, sld[:i] + rep + sld[i + 1:], "keyboard-sub", sld)
        return out

    def homoglyph_ascii(self, sld: str) -> dict:
        out = {}
        for i, ch in enumerate(sld):
            for rep in HOMOGLYPH_ASCII.get(ch, []):
                _add(out, sld[:i] + rep + sld[i + 1:], "homoglyph-ascii", sld)
        # double-char expansions like m->rn already handled; also w->vv etc.
        return out

    def homoglyph_unicode(self, sld: str) -> dict:
        out = {}
        for i, ch in enumerate(sld):
            for rep in HOMOGLYPH_UNICODE.get(ch, []):
                _add(out, sld[:i] + rep + sld[i + 1:], "homoglyph-unicode", sld)
        return out

    def bitsquat(self, sld: str) -> dict:
        """Flip each bit of each char; keep results that are valid DNS chars."""
        out = {}
        valid = set(string.ascii_lowercase + string.digits + "-")
        for i, ch in enumerate(sld):
            o = ord(ch)
            for b in range(7):  # 7 bits covers ascii letters/digits
                c = chr(o ^ (1 << b))
                c = c.lower()
                if c != ch and c in valid:
                    _add(out, sld[:i] + c + sld[i + 1:], "bitsquat", sld)
        return out

    def hyphenate(self, sld: str) -> dict:
        out = {}
        for i in range(1, len(sld)):
            _add(out, sld[:i] + "-" + sld[i:], "hyphenation", sld)
        # hyphen removal is covered implicitly when input has hyphens
        if "-" in sld:
            _add(out, sld.replace("-", ""), "hyphen-removal", sld)
        return out

    def dot_split(self, sld: str) -> dict:
        """paypaI -> pay.pal style subdomain tricks (returned as full host)."""
        out = {}
        for i in range(1, len(sld)):
            v = sld[:i] + "." + sld[i:]
            if v not in out:
                out[v] = "subdomain-dot"
        return out

    def vowel_swap(self, sld: str) -> dict:
        out = {}
        for i, ch in enumerate(sld):
            if ch in VOWELS:
                for v in VOWELS:
                    if v != ch:
                        _add(out, sld[:i] + v + sld[i + 1:], "vowel-swap", sld)
        return out

    def pluralize(self, sld: str) -> dict:
        out = {}
        _add(out, sld + "s", "pluralisation", sld)
        if sld.endswith("s"):
            _add(out, sld[:-1], "singularisation", sld)
        return out

    def affix(self, sld: str) -> dict:
        out = {}
        for p in PREFIXES:
            _add(out, f"{p}-{sld}", "prefix", sld)
            _add(out, f"{p}{sld}", "prefix-join", sld)
        for s in SUFFIXES:
            _add(out, f"{sld}-{s}", "suffix", sld)
            _add(out, f"{sld}{s}", "suffix-join", sld)
        return out

    # -- orchestrator ---------------------------------------------------------
    def generate(self, domain: str) -> list[dict]:
        """Return [{'variant': fqdn, 'technique': str, 'sld_variant': str}]."""
        sld, tld = split_domain(domain)
        merged: dict[str, str] = {}
        for fn in (self.omission, self.transposition, self.duplication,
                   self.keyboard_sub, self.homoglyph_ascii, self.bitsquat,
                   self.hyphenate, self.vowel_swap, self.pluralize,
                   self.affix, self.insertion):
            for k, v in fn(sld).items():
                if k not in merged:
                    merged[k] = v
                if len(merged) >= self.max_variants:
                    break
        if self.include_unicode:
            for k, v in self.homoglyph_unicode(sld).items():
                if k not in merged:
                    merged[k] = v
                if len(merged) >= self.max_variants:
                    break

        dot_hosts = self.dot_split(sld)  # handled separately (contain a dot)

        results = []
        for svar, tech in list(merged.items())[:self.max_variants]:
            results.append({"variant": f"{svar}.{tld}", "technique": tech,
                            "sld_variant": svar, "tld": tld})
        for host, tech in dot_hosts.items():
            results.append({"variant": f"{host}.{tld}", "technique": tech,
                            "sld_variant": host, "tld": tld})

        if self.include_tld:
            for alt in COMMON_TLDS:
                if alt != tld:
                    results.append({"variant": f"{sld}.{alt}",
                                    "technique": "tld-swap",
                                    "sld_variant": sld, "tld": alt})
        # de-dup preserving order
        seen, final = set(), []
        for r in results:
            if r["variant"] not in seen:
                seen.add(r["variant"])
                final.append(r)
        return final[:self.max_variants + len(COMMON_TLDS) + len(dot_hosts)]


def generate_variants(domain: str, include_unicode: bool = False,
                      include_tld: bool = True,
                      max_variants: int = 5000) -> list[dict]:
    return TyposquatGenerator(include_unicode, include_tld,
                              max_variants).generate(domain)
