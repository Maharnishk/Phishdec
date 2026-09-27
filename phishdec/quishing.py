"""Quishing scanner: decode QR codes + analyse destinations + awareness kit."""
from __future__ import annotations

import os
from .enrich import analyze_url


def decode_qr(image_path: str) -> list[str]:
    """Decode QR payloads from an image. Tries pyzbar, then OpenCV.

    Returns list of decoded strings (may be empty).
    """
    if not os.path.exists(image_path):
        raise FileNotFoundError(image_path)
    payloads: list[str] = []

    # 1) pyzbar (best accuracy) — optional
    try:
        from pyzbar.pyzbar import decode as zbar_decode
        from PIL import Image
        for obj in zbar_decode(Image.open(image_path)):
            try:
                payloads.append(obj.data.decode("utf-8", "replace"))
            except Exception:
                pass
        if payloads:
            return payloads
    except Exception:
        pass

    # 2) OpenCV QRCodeDetector (no extra system DLLs needed)
    try:
        import cv2  # type: ignore
        img = cv2.imread(image_path)
        if img is None:
            return payloads
        det = cv2.QRCodeDetector()
        # multi first (newer opencv), fallback single
        try:
            ok, decoded, _, _ = det.detectAndDecodeMulti(img)
            if ok and decoded:
                return [d for d in decoded if d]
        except Exception:
            pass
        data, _, _ = det.detectAndDecode(img)
        if data:
            return [data]
    except Exception as e:
        raise RuntimeError(
            "QR decoding needs opencv-python (pip install opencv-python) "
            f"or pyzbar. Details: {e}") from e
    return payloads


def scan_qr_image(image_path: str, legit_domains: list[str] | None = None) -> dict:
    """Decode a QR image and analyse every payload URL."""
    payloads = decode_qr(image_path)
    findings = []
    for p in payloads:
        a = analyze_url(p, legit_domains)
        findings.append({"payload": p, **a})
    worst = max([f["score"] for f in findings], default=0)
    verdict = ("CRITICAL" if worst >= 75 else "HIGH" if worst >= 50
               else "MEDIUM" if worst >= 30 else "LOW" if worst >= 10 else "CLEAR")
    return {"image": image_path, "payloads": payloads, "findings": findings,
            "score": worst, "verdict": "NO-QR-FOUND" if not payloads else verdict}


def scan_qr_text(payload: str, legit_domains: list[str] | None = None) -> dict:
    """Analyse a QR payload string directly (e.g. from a phone scan)."""
    a = analyze_url(payload, legit_domains)
    return {"payload": payload, **a}


# --- awareness / test-QR generation ------------------------------------------

def generate_test_qr(url: str, output_path: str) -> str:
    """Create a QR PNG for `url` (for security-awareness exercises)."""
    try:
        import qrcode  # type: ignore
    except Exception as e:
        raise RuntimeError("pip install qrcode[pil] to generate QRs") from e
    img = qrcode.make(url)
    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
    img.save(output_path)
    return output_path


def generate_awareness_kit(legit_domain: str, outdir: str = "awareness_kit") -> list[dict]:
    """Build a labelled set of benign + malicious demo QRs for training.

    Returns manifest [{'label','url','file','expected_verdict'}].
    """
    os.makedirs(outdir, exist_ok=True)
    sld, _, tld = legit_domain.lower().rstrip(".").rpartition(".")
    sld = sld.split(".")[-1]
    cases = [
        ("01-legit", f"https://{legit_domain}/login", "CLEAR"),
        ("02-typosquat-letter-swap", f"https://{sld[:-1]}{sld[-2]}.{tld}/login", "HIGH"),
        ("03-homoglyph-zero", f"https://{sld.replace('o', '0')}.{tld}/login", "HIGH"),
        ("04-wrong-tld", f"https://{sld}.xyz/login", "MEDIUM"),
        ("05-shortener", "https://bit.ly/3xAmP1e", "MEDIUM"),
        ("06-ip-host", "http://185.22.14.9/secure-login", "HIGH"),
        ("07-at-trick", f"http://{legit_domain}@evil.example/login", "CRITICAL"),
        ("08-punycode", "https://xn--pypal-4ve.com/login", "HIGH"),
        ("09-subdomain-spoof", f"https://{legit_domain}.evil.example/login", "MEDIUM"),
        ("10-http-downgrade", f"http://{legit_domain}/login", "LOW"),
    ]
    manifest = []
    for label, url, expected in cases:
        fp = os.path.join(outdir, f"{label}.png")
        try:
            generate_test_qr(url, fp)
            status = "ok"
        except Exception as e:
            status = f"qr-lib-missing: {e}"
            fp = ""
        manifest.append({"label": label, "url": url, "file": fp,
                         "expected": expected, "status": status})
    return manifest
