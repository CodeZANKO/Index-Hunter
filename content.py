"""Content fetching + analysis.

Fetches a *preview* (bounded byte range, default 64KB) of a candidate file by
default, or the *full* file when full_scan is enabled. Then runs magic-byte
type detection, secret classification, entropy analysis and optional YARA.
"""
import asyncio
import io

from signatures import (
    scan_secrets, scan_entropy, detect_magic, check_type_mismatch,
    detect_clouds,
)

PREVIEW_BYTES = 64 * 1024  # 64 KB default preview window


async def fetch_content(session, url: str, full_scan: bool, max_full: int = 5 * 1024 * 1024):
    """Return (data: bytes, truncated: bool, status) for a URL."""
    headers = {}
    if not full_scan:
        headers["Range"] = f"bytes=0-{PREVIEW_BYTES - 1}"
    try:
        async with session.get(url, headers=headers, timeout=30, allow_redirects=True) as resp:
            status = resp.status
            if status == 206 or status == 200:
                data = await resp.read()
            else:
                return b"", False, status
            truncated = False
            if full_scan and len(data) >= max_full:
                data = data[:max_full]
                truncated = True
            if not full_scan and len(data) >= PREVIEW_BYTES:
                truncated = True
            return data, truncated, status
    except Exception:
        return b"", False, 0


def _decode(data: bytes):
    for enc in ("utf-8", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "ignore")


def analyze_content(data: bytes, filename: str, extension: str, run_yara=None):
    """Run all content-based detectors on fetched bytes.

    run_yara: optional callable(text, data) -> list of yara match dicts.
    Returns a dict with detected_type, mismatch, secrets, entropy, yara, cloud.
    """
    text = _decode(data)
    detected_type = detect_magic(data[:512])

    mismatch = check_type_mismatch(extension, detected_type) if extension else False

    secrets = scan_secrets(text)
    entropy = scan_entropy(text)
    cloud = detect_clouds(text)

    yara = []
    if run_yara:
        try:
            yara = run_yara(text, data) or []
        except Exception:
            yara = []

    return {
        "detected_type": detected_type,
        "mismatch": mismatch,
        "secrets": secrets,
        "entropy": entropy,
        "cloud": cloud,
        "yara": yara,
    }


def mask_preview(text: str, max_lines: int = 40, max_len: int = 2000):
    """Produce a small, secret-masked preview of file text for display."""
    lines = text.splitlines()[:max_lines]
    out = []
    secret_terms = ("password", "passwd", "secret", "token", "api_key", "apikey",
                    "access_key", "private_key", "client_secret", "auth", "key")
    for ln in lines:
        low = ln.lower()
        if any(t in low for t in secret_terms):
            # mask value after assignment
            if "=" in ln or ":" in ln:
                sep = "=" if "=" in ln else ":"
                k, _, v = ln.partition(sep)
                ln = f"{k}{sep} {'*' * max(len(v.strip().strip(chr(34)).strip(chr(39))), 6)}"
        if len(ln) > max_len:
            ln = ln[:max_len] + "..."
        out.append(ln)
    return "\n".join(out)
