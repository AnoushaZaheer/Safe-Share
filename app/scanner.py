"""
Scan a sanitized project for anything that still looks sensitive.
Used as the final verification step before uploading anywhere.
"""

import re
from datetime import datetime
from pathlib import Path

from publisher import iter_text_files
from sanitizer import DEFAULT_SAFE_DOMAINS

PATTERNS = {
    "URL": r"https?://[^\s\"'<>]+",
    "Email": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    "Windows Path": r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n&]+\\)+[^\\/:*?\"<>|\r\n&]*",
    "UNC Path": r"\\\\[A-Za-z0-9._$-]+\\[^\s\"'<>]+",
    "IP Address": r"\b(?!0\.0\.0\.0)(?!127\.)(?:\d{1,3}\.){3}\d{1,3}\b",
    "Possible Secret": r"(?i)(?:password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*[\"']?[^\s\"'<>]{6,}",
}


def scan(config, target=None):
    """Scan target (default: destination) and return a list of findings."""
    root = Path(target or config["destination"])
    if not root.exists():
        raise FileNotFoundError(f"Nothing to scan, folder not found: {root}")

    ignore_patterns = [p.lower() for p in config["ignore_patterns"]]
    ignore_patterns += [d.lower() for d in config.get("safe_domains", [])]
    ignore_patterns += list(DEFAULT_SAFE_DOMAINS)
    # Placeholders introduced by the sanitizer are not findings.
    placeholders = {"example.com", r"c:\users\user", r"c:\path",
                    r"\\server\share", "user@example.com", "0.0.0.0",
                    "redacted", "server=server;",
                    "{x:null}"}  # UiPath boilerplate for "no password set"

    findings = []
    seen = set()

    print(f"[>] Scanning {root} ...")

    for file in iter_text_files(root, config):
        try:
            content = file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        rel = str(file.relative_to(root))

        for name, pattern in PATTERNS.items():
            for match in re.findall(pattern, content):
                value = match.lower()

                if any(p in value for p in ignore_patterns):
                    continue
                if any(p in value for p in placeholders):
                    continue

                key = (rel, name, match)
                if key in seen:
                    continue
                seen.add(key)

                findings.append({"file": rel, "type": name, "value": match})

    return findings


def generate_report(config, findings, report_path=None):
    """Write findings to Reports/ScanReport.txt."""
    if report_path:
        report_file = Path(report_path)
        report_file.parent.mkdir(parents=True, exist_ok=True)
    else:
        report_dir = Path(__file__).parent.parent / "Reports"
        report_dir.mkdir(exist_ok=True)
        report_file = report_dir / "ScanReport.txt"

    with open(report_file, "w", encoding="utf-8") as f:
        f.write("=========================================\n")
        f.write("         Safe Share Scan Report\n")
        f.write("=========================================\n\n")
        f.write(f"Generated      : {datetime.now():%Y-%m-%d %H:%M:%S}\n")
        f.write(f"Scanned folder : {config['destination']}\n")
        f.write(f"Total findings : {len(findings)}\n")

        current_file = None
        for item in findings:
            if item["file"] != current_file:
                current_file = item["file"]
                f.write(f"\n{current_file}\n")
                f.write("-" * len(current_file) + "\n")
            f.write(f"[{item['type']}] {item['value']}\n")

        if not findings:
            f.write("\nNo sensitive information detected. Safe to share!\n")

    print(f"[+] Report saved to: {report_file}")

    if findings:
        print(f"[!] {len(findings)} potential issue(s) remain - review the report "
              f"and add entries to 'replace' or 'ignore_patterns' in config.json.")
    else:
        print("[+] Clean scan. Project looks safe to share.")

    return report_file
