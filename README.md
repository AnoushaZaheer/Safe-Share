# Safe Share

Prepare coding projects (UiPath, or any text-based project) for safe public sharing on GitHub, portfolios, or anywhere else. Safe Share copies your project to a clean folder, replaces all sensitive information at once, then scans the result and produces a report so you can verify nothing leaked.

It handles two kinds of sensitive data:

- **Automatic**: Windows user folders, emails, non-framework URLs, UNC network paths, IP addresses, connection strings, and API keys / tokens / passwords in `key = value` form are detected and replaced with safe placeholders — no configuration needed.
- **Custom**: company names, internal hostnames, usernames, or anything else specific to your project, defined once in the `replace` map of `config.json`.

No dependencies — pure Python 3.8+ standard library.

## Quick start

```bash
# 1. Create your config
python app/main.py init

# 2. Edit config/config.json - set source, destination, and custom replacements

# 3. See what sensitive info exists in your project
python app/main.py discover

# 4. Preview what would change
python app/main.py publish --dry-run

# 5. Publish for real: copy -> sanitize -> scan -> report
python app/main.py publish
```

If the final scan is clean, the sanitized copy in your destination folder is ready to upload.

## Commands

| Command | What it does |
|---|---|
| `init` | Creates `config/config.json` from the example template (`--force` to overwrite) |
| `discover` | Scans the **source** project and lists URLs, emails, paths, users, IPs, secrets — use this to build your `replace` map |
| `publish` | Copies source → destination (skipping `ignore` folders), runs all sanitizers, then scans and writes `Reports/ScanReport.txt`. `--dry-run` previews without writing. |
| `scan` | Re-scans the destination anytime and regenerates the report |

All commands accept `-c path/to/config.json`, and `--source` / `--dest` overrides where relevant. `publish` and `scan` exit with code `2` if findings remain, so you can use them in scripts or CI.

## Configuration

```jsonc
{
    "source": "C:\\path\\to\\your\\project",        // original project (never modified)
    "destination": "C:\\path\\to\\sanitized\\copy", // wiped and recreated on publish

    "replace": {                                    // your project-specific values
        "internal.yourcompany.com": "example.com",
        "Your Company": "Demo Company"
    },

    "ignore": [".git", ".local", "__pycache__"],    // folders not copied at all
    "extensions": [".xaml", ".json", ".xml"],       // file types to sanitize/scan
    "safe_domains": ["github.com"],                 // URLs/emails on these domains are kept
    "ignore_patterns": [],                          // scan findings containing these are ignored

    "auto_sanitize": {                              // toggle or re-word any auto rule
        "emails": { "enabled": true, "placeholder": "user@example.com" },
        "urls":   { "enabled": false }
    }
}
```

Framework domains (`schemas.microsoft.com`, `cloud.uipath.com`, `openxmlformats.org`, `www.w3.org`, etc.) are always preserved so UiPath `.xaml` files keep working.

## Safety notes

- Your **source project is never modified** — all changes happen in the destination copy.
- `config/config.json` and `Reports/` are in `.gitignore` because they contain your real values. Never commit them.
- Always review `Reports/ScanReport.txt` before uploading. A clean scan is strong evidence, not a guarantee — automated tools can't know everything that's sensitive to *you*.

## Project structure

```
safe-share/
├── app/
│   ├── main.py        # CLI entry point
│   ├── publisher.py   # config loading, copy, sanitize orchestration
│   ├── sanitizer.py   # automatic sanitization rules
│   ├── scanner.py     # post-sanitization verification + report
│   └── discover.py    # pre-publish discovery of sensitive info
├── config/
│   ├── config.example.json
│   └── config.json    # your real config (gitignored)
├── Reports/           # scan reports (gitignored)
└── README.md
```
