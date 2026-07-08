"""
Safe Share - prepare coding projects for safe public sharing.

Workflow:
    1. python app/main.py init                 create a config file
    2. edit config/config.json                 set source, destination, replacements
    3. python app/main.py discover             see what's sensitive in the source
    4. python app/main.py publish              copy + sanitize + scan + report
    5. python app/main.py scan                 re-verify the sanitized copy anytime
"""

import argparse
import json
import shutil
import sys
from pathlib import Path

from publisher import load_config, copy_project, sanitize, DEFAULT_CONFIG_PATH
from scanner import scan, generate_report
from discover import discover, print_results


def apply_overrides(config, args):
    """Let --source / --dest on the command line override config.json."""
    if getattr(args, "source", None):
        config["source"] = args.source
    if getattr(args, "dest", None):
        config["destination"] = args.dest
    return config


def cmd_init(args):
    target = Path(args.config) if args.config else DEFAULT_CONFIG_PATH
    example = target.parent / "config.example.json"

    if target.exists() and not args.force:
        print(f"[!] {target} already exists. Use --force to overwrite.")
        return 1

    target.parent.mkdir(parents=True, exist_ok=True)

    if example.exists():
        shutil.copy(example, target)
    else:
        target.write_text(json.dumps(DEFAULT_CONFIG_TEMPLATE, indent=4),
                          encoding="utf-8")

    print(f"[+] Config created: {target}")
    print("    Edit it to set your source, destination and replacements.")
    return 0


def cmd_discover(args):
    config = apply_overrides(load_config(args.config), args)
    results = discover(config, target=args.source or config["source"])
    print_results(results)
    return 0


def cmd_publish(args):
    config = apply_overrides(load_config(args.config), args)

    copy_project(config)
    sanitize(config, dry_run=args.dry_run)

    if args.dry_run:
        print("\n[i] Dry run - skipping scan/report. "
              "Run without --dry-run to apply changes.")
        return 0

    findings = scan(config)
    generate_report(config, findings)

    if findings:
        print("\n[!] Publish finished WITH findings - review before uploading.")
        return 2

    print("\n[+] Publish completed successfully. Safe to upload.")
    return 0


def cmd_scan(args):
    config = apply_overrides(load_config(args.config), args)
    findings = scan(config)
    generate_report(config, findings)
    return 2 if findings else 0


DEFAULT_CONFIG_TEMPLATE = {
    "source": "C:\\path\\to\\your\\project",
    "destination": "C:\\path\\to\\sanitized\\copy",
    "replace": {
        "https://internal.yourcompany.com": "https://example.com",
        "Your Company Name": "Demo Company",
        "your.username": "demo.user",
        "YourRealPassword": "<PASSWORD>"
    },
    "ignore": [
        ".git", ".local", ".project", ".screenshots",
        ".templates", ".tmh", "__pycache__", "node_modules", ".venv"
    ],
    "extensions": [
        ".xaml", ".json", ".xml", ".txt", ".csv",
        ".config", ".md", ".py", ".cs", ".vb", ".yaml", ".yml"
    ],
    "safe_domains": [
        "github.com"
    ],
    "ignore_patterns": [],
    "auto_sanitize": {
        "windows_users": {"enabled": True, "placeholder": "USER"},
        "emails": {"enabled": True, "placeholder": "user@example.com"},
        "urls": {"enabled": True, "placeholder": "https://example.com"},
        "network_paths": {"enabled": True, "placeholder": "\\\\SERVER\\share"},
        "ip_addresses": {"enabled": True, "placeholder": "0.0.0.0"},
        "connection_strings": {"enabled": True, "placeholder": "Server=SERVER;"},
        "api_keys": {"enabled": True, "placeholder": "REDACTED"}
    }
}


def main():
    parser = argparse.ArgumentParser(
        prog="safe-share",
        description="Prepare coding projects for safe public sharing.",
        epilog="Typical flow: init -> edit config -> discover -> publish",
    )
    parser.add_argument("-c", "--config", help="Path to config.json "
                        "(default: config/config.json)")

    sub = parser.add_subparsers(dest="command")

    p_init = sub.add_parser("init", help="Create a starter config file")
    p_init.add_argument("--force", action="store_true",
                        help="Overwrite existing config")

    p_disc = sub.add_parser("discover",
                            help="List sensitive info found in the SOURCE project")
    p_disc.add_argument("--source", help="Override source folder")

    p_pub = sub.add_parser("publish",
                           help="Copy, sanitize, scan and generate a report")
    p_pub.add_argument("--source", help="Override source folder")
    p_pub.add_argument("--dest", help="Override destination folder")
    p_pub.add_argument("--dry-run", action="store_true",
                       help="Show what would change without writing files")

    p_scan = sub.add_parser("scan", help="Re-scan the sanitized destination")
    p_scan.add_argument("--dest", help="Override destination folder")

    args = parser.parse_args()

    commands = {
        "init": cmd_init,
        "discover": cmd_discover,
        "publish": cmd_publish,
        "scan": cmd_scan,
    }

    if args.command not in commands:
        parser.print_help()
        return 0

    try:
        return commands[args.command](args)
    except (FileNotFoundError, KeyError, ValueError) as e:
        print(f"\n[x] Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
