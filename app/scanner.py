import re
from pathlib import Path


PATTERNS = {
    "URL": r"https?://[^\s\"'>]+",
    "Email": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    "Windows Path": r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*"
}


def scan(config):


    destination = Path(config["destination"])

    findings = []
    seen = set()

    print("🔍 Scanning project...")

    for file in destination.rglob("*"):

        if not file.is_file():
            continue

        if file.suffix.lower() not in config["extensions"]:
            continue

        try:
            content = file.read_text(encoding="utf-8")
        except Exception:
            continue

        for name, pattern in PATTERNS.items():

            matches = re.findall(pattern, content)

            for match in matches:

                # Ignore known safe values
                ignore = False

                for item in config["ignore_patterns"]:
                    if item.lower() in match.lower():
                        ignore = True
                        break

                if ignore:
                    continue

                key = (
                    str(file.relative_to(destination)),
                    name,
                    match
                )

                if key in seen:
                    continue

                seen.add(key)

                findings.append({
                    "file": str(file.relative_to(destination)),
                    "type": name,
                    "value": match
                })

    return findings



def generate_report(config, findings):

    report_dir = Path(__file__).parent.parent / "Reports"
    report_dir.mkdir(exist_ok=True)

    report_file = report_dir / "ScanReport.txt"

    with open(report_file, "w", encoding="utf-8") as f:

        f.write("=========================================\n")
        f.write("         Safe Share Scan Report\n")
        f.write("=========================================\n\n")

        f.write(f"Total Findings : {len(findings)}\n\n")

        current_file = ""

        for item in findings:

            if item["file"] != current_file:
                current_file = item["file"]
                f.write(f"\n{current_file}\n")
                f.write("-" * len(current_file) + "\n")

            f.write(f"[{item['type']}] {item['value']}\n")

    print(f"\n📄 Report saved to: {report_file}")