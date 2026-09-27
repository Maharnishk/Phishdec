"""PhishDec — Phishing Domain Generator & Quishing Scanner."""
from .generator import TyposquatGenerator, generate_variants
from .enrich import score_domain, enrich_results
from .checker import check_domain, check_bulk

__all__ = [
    "TyposquatGenerator",
    "generate_variants",
    "score_domain",
    "enrich_results",
    "check_domain",
    "check_bulk",
]

__version__ = "1.0.0"
