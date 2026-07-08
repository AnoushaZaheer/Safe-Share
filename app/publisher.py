"""
Copy a project to a clean destination and sanitize it.
"""

import json
import shutil
from pathlib import Path

from sanitizer import run_auto_sanitizers

DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config" / "config.json"


def load_config(path=None):
    """Load configuration from JSON, with basic validation."""
    config_path = Path(path) if path else DEFAULT_CONFIG_PATH

    if not config_path.exists():
        raise FileNotFoundError(
            f"Configuration file not found: {config_path}\n"
            f"Run 'python app/main.py init' to create one."
        )

    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)

    for key in ("source", "destination", "extensions"):
        if key not in config:
            raise KeyError(f"Missing required config key: '{key}'")

    config.setdefault("replace", {})
    config.setdefault("ignore", [])
    config.setdefault("ignore_patterns", [])
    config.setdefault("safe_domains", [])
    config.setdefault("auto_sanitize", {})
    config["extensions"] = [e.lower() for e in config["extensions"]]

    return config


def iter_text_files(root, config):
    """Yield files under root that match the configured extensions."""
    root = Path(root)
    for file in root.rglob("*"):
        if file.is_file() and file.suffix.lower() in config["extensions"]:
            yield file


def copy_project(config):
    """Copy the source project to the destination (destination is wiped first)."""
    source = Path(config["source"])
    destination = Path(config["destination"])

    if not source.exists():
        raise FileNotFoundError(f"Source project not found: {source}")

    if destination.resolve() == source.resolve():
        raise ValueError("Source and destination must be different folders.")

    if destination.exists():
        print("[-] Removing old copy...")
        shutil.rmtree(destination)

    print(f"[>] Copying project:\n    {source}\n    -> {destination}")

    shutil.copytree(
        source,
        destination,
        ignore=shutil.ignore_patterns(*config["ignore"]),
    )

    print("[+] Project copied.")


def sanitize(config, dry_run=False):
    """
    Sanitize all supported files in the destination.

    1. Auto-sanitizers (user folders, emails, URLs, keys, ...)
    2. User-defined replacements from config["replace"]
    """
    destination = Path(config["destination"])
    if not destination.exists():
        raise FileNotFoundError(
            f"Destination not found: {destination}\nRun 'publish' first."
        )

    files_modified = 0
    auto_totals = {}
    custom_total = 0
    all_changes = []  # (file, rule, old, new)

    mode = "DRY RUN - no files will be written" if dry_run else "writing changes"
    print(f"[>] Sanitizing files ({mode})...")

    for file in iter_text_files(destination, config):
        try:
            content = file.read_text(encoding="utf-8", errors="ignore")
        except OSError as e:
            print(f"[!] Skipped {file.name}: {e}")
            continue

        original = content
        rel = str(file.relative_to(destination))
        file_changes = []

        # 1. Automatic sanitization
        content, stats = run_auto_sanitizers(content, config,
                                             changes=file_changes)
        for rule, count in stats.items():
            auto_totals[rule] = auto_totals.get(rule, 0) + count

        # 2. User-defined replacements
        for old, new in config["replace"].items():
            if not old:
                continue
            count = content.count(old)
            if count:
                custom_total += count
                content = content.replace(old, new)
                file_changes.extend([("custom", old, new)] * count)

        for rule, old, new in file_changes:
            all_changes.append((rel, rule, old, new))

        if content != original:
            files_modified += 1
            if not dry_run:
                file.write_text(content, encoding="utf-8")

    write_change_log(all_changes, dry_run=dry_run)

    print()
    print("=" * 50)
    print("Sanitization Summary" + (" (dry run)" if dry_run else ""))
    print("=" * 50)
    print(f"Files modified      : {files_modified}")
    print(f"Custom replacements : {custom_total}")
    for rule, count in sorted(auto_totals.items()):
        print(f"Auto [{rule:<19}]: {count}")
    print("=" * 50)

    return files_modified


def write_change_log(changes, dry_run=False):
    """
    Write Reports/Changes.txt: every replacement made, before -> after,
    grouped by file, duplicates collapsed with a count.
    """
    from datetime import datetime

    report_dir = Path(__file__).parent.parent / "Reports"
    report_dir.mkdir(exist_ok=True)
    log_file = report_dir / "Changes.txt"

    # Collapse duplicates: same (file, rule, old, new) shown once with count.
    counted = {}
    order = []
    for key in changes:
        if key not in counted:
            counted[key] = 0
            order.append(key)
        counted[key] += 1

    with open(log_file, "w", encoding="utf-8") as f:
        f.write("=========================================\n")
        f.write("        Safe Share Change Log\n")
        f.write("=========================================\n\n")
        f.write(f"Generated : {datetime.now():%Y-%m-%d %H:%M:%S}")
        f.write("  (DRY RUN - nothing was written)" if dry_run else "")
        f.write(f"\nTotal replacements : {sum(counted.values())}\n")
        f.write("\nNOTE: This file contains your ORIGINAL sensitive values.\n")
        f.write("It stays in Reports/ (gitignored). Never share or commit it.\n")

        current_file = None
        for file, rule, old, new in order:
            if file != current_file:
                current_file = file
                f.write(f"\n{file}\n")
                f.write("-" * len(file) + "\n")
            times = counted[(file, rule, old, new)]
            suffix = f"   (x{times})" if times > 1 else ""
            f.write(f"[{rule}]{suffix}\n")
            f.write(f"    - {old}\n")
            f.write(f"    + {new}\n")

        if not order:
            f.write("\nNo replacements were made.\n")

    print(f"[+] Change log saved to: {log_file}")
