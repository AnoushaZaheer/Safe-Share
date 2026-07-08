"""
Discover sensitive information in the SOURCE project, before publishing.
Use this first to decide what to add to config.json's "replace" map.
"""

import re
from collections import defaultdict
from pathlib import Path

from publisher import iter_text_files
from sanitizer import DEFAULT_SAFE_DOMAINS

PATTERNS = {
    "Client URLs": r"https?://[^\s\"'<>]+",
    "Emails": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    "Windows Users": r"(?i)[A-Za-z]:\\Users\\([^\\/:*?\"<>|\r\n&]+)",
    "Files": r"[A-Za-z]:\\[^\"'\r\n<>&]+?\.(?:xlsx|xls|csv|txt|pdf|docx?|json|xml|zip|config)",
    "Folders": r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n&]+\\)+",
    "Network Paths": r"\\\\[A-Za-z0-9._$-]+\\[^\r\n\"'<>&]+",
    "IP Addresses": r"\b(?!0\.0\.0\.0)(?!127\.)(?:\d{1,3}\.){3}\d{1,3}\b",
    "Connection Strings": r"(?i)Server=.*?;.*?Database=.*?;",
    "API Keys / Secrets": r"(?i)(?:api[_-]?key|apikey|token|secret|password|pwd)\s*[:=]\s*[\"']?([^\s\"'<>]{6,})",
}

# XML entities that mark the end of a clean value in .xaml files
XML_NOISE = ("&quot;", "&#xD;", "&#xA;", "&amp;", "&lt;", "&gt;")


def clean(value):
    """Trim XML entities and anything after them (VB code bleed in .xaml)."""
    value = str(value)
    for noise in XML_NOISE:
        idx = value.find(noise)
        if idx != -1:
            value = value[:idx]
    return value.strip().rstrip("\\").strip()


def discover(config, target=None, safe_domains=None):
    """Scan the source (default) and group unique findings by category."""
    root = Path(target or config["source"])
    if not root.exists():
        raise FileNotFoundError(f"Project not found: {root}")

    safe = set(d.lower() for d in (safe_domains or []))
    safe |= set(d.lower() for d in config.get("safe_domains", []))
    safe |= DEFAULT_SAFE_DOMAINS
    safe |= set(p.lower() for p in config.get("ignore_patterns", []))

    results = defaultdict(set)

    print(f"\n[>] Discovering sensitive information in:\n    {root}\n")

    for file in iter_text_files(root, config):
        try:
            text = file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for category, pattern in PATTERNS.items():
            for match in re.findall(pattern, text):
                if isinstance(match, tuple):
                    match = " | ".join(m for m in match if m)

                value = clean(match)

                if len(value) < 3:
                    continue

                lowered = value.lower()
                if category in ("Client URLs", "Emails") and any(
                    d in lowered for d in safe
                ):
                    continue
                if any(p in lowered for p in safe):
                    continue

                results[category].add(f"{file.name}  -->  {value}")

    return results


def print_results(results):
    print("=" * 55)
    print("          Discovered Sensitive Information")
    print("=" * 55)

    total = 0
    for category in sorted(results):
        values = sorted(results[category])
        if not values:
            continue
        total += len(values)
        print(f"\n{category}")
        print("-" * len(category))
        for item in values:
            print(item)

    print("\n" + "=" * 55)
    print(f"Total findings : {total}")
    print("=" * 55)

    if total:
        print(
            "\nNext step: add company names, usernames, passwords, and other\n"
            "project-specific values to the \"replace\" map in config.json,\n"
            "then run: python app/main.py publish"
        )
