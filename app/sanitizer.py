"""
Automatic sanitizers.

Each function takes text and returns (new_text, replacement_count).
Pass a list as `log` to record (old, new) pairs for the change report.
These handle the common cases automatically; anything project-specific
goes in the "replace" map in config.json.
"""

import re

# Framework / vendor domains that are safe to leave in place.
DEFAULT_SAFE_DOMAINS = {
    "schemas.microsoft.com",
    "schemas.uipath.com",
    "cloud.uipath.com",
    "cv.uipath.com",
    "ocr.uipath.com",
    "du.uipath.com",
    "openxmlformats.org",
    "www.w3.org",
    "example.com",
    "localhost",
}

RE_WINDOWS_USER = re.compile(r"(?i)([A-Za-z]:\\Users\\)([^\\/:*?\"<>|\r\n&]+)")
RE_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
RE_URL = re.compile(r"https?://[^\s\"'<>]+")
RE_UNC = re.compile(r"\\\\[A-Za-z0-9._$-]+(\\[^\\\r\n\"'<>|;]+)+")
RE_LOCAL_PATH = re.compile(
    r"(?<![\\\w])([A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n&]+\\)+[^\\/:*?\"<>|\r\n&]*)"
)
RE_IP = re.compile(
    r"\b(?!0\.0\.0\.0)(?!127\.)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
RE_CONN_STRING = re.compile(r"(?i)Server\s*=\s*[^;\"'\r\n]+;")
RE_API_KEY = re.compile(
    r"(?i)((?:api[_-]?key|apikey|token|secret)\s*[:=]\s*[\"']?)([A-Za-z0-9_\-]{10,})"
)


def _is_safe_url(url, safe_domains):
    lowered = url.lower()
    return any(domain in lowered for domain in safe_domains)


def _record(log, old, new):
    if log is not None and old != new:
        log.append((old, new))


def sanitize_windows_users(text, placeholder="USER", log=None):
    """C:\\Users\\JohnDoe\\...  ->  C:\\Users\\USER\\..."""
    count = 0

    def repl(m):
        nonlocal count
        if m.group(2).lower() in ("public", "default", placeholder.lower()):
            return m.group(0)
        count += 1
        new = m.group(1) + placeholder
        _record(log, m.group(0), new)
        return new

    return RE_WINDOWS_USER.sub(repl, text), count


def sanitize_emails(text, placeholder="user@example.com", safe_domains=None,
                    log=None):
    """Replace email addresses, keeping ones on safe domains."""
    safe_domains = safe_domains or set()
    count = 0

    def repl(m):
        nonlocal count
        value = m.group(0).lower()
        if value == placeholder or any(d in value for d in safe_domains):
            return m.group(0)
        count += 1
        _record(log, m.group(0), placeholder)
        return placeholder

    return RE_EMAIL.sub(repl, text), count


def sanitize_urls(text, placeholder="https://example.com", safe_domains=None,
                  log=None):
    """Replace URLs unless the domain is on the safe list."""
    safe_domains = safe_domains or DEFAULT_SAFE_DOMAINS
    count = 0

    def repl(m):
        nonlocal count
        if _is_safe_url(m.group(0), safe_domains):
            return m.group(0)
        count += 1
        _record(log, m.group(0), placeholder)
        return placeholder

    return RE_URL.sub(repl, text), count


def sanitize_network_paths(text, placeholder=r"\\SERVER\share", log=None):
    """\\\\fileserver01\\finance\\...  ->  \\\\SERVER\\share"""
    count = 0

    def repl(m):
        nonlocal count
        count += 1
        _record(log, m.group(0), placeholder)
        return placeholder

    return RE_UNC.sub(repl, text), count


def sanitize_local_paths(text, placeholder="C:\\PATH", log=None):
    """
    D:\\John Doe\\Reports\\file.xlsx  ->  C:\\PATH\\file.xlsx
    Disabled by default: replacing paths can break projects that need them.
    """
    count = 0

    def repl(m):
        nonlocal count
        value = m.group(1)
        if value.lower().startswith(("c:\\users\\user", placeholder.lower())):
            return m.group(0)
        count += 1
        filename = value.rstrip("\\").split("\\")[-1]
        new = f"{placeholder}\\{filename}" if "." in filename else placeholder
        _record(log, m.group(0), new)
        return new

    return RE_LOCAL_PATH.sub(repl, text), count


def sanitize_ips(text, placeholder="0.0.0.0", log=None):
    """Replace IPv4 addresses (loopback and version-like numbers excluded)."""
    count = 0

    def repl(m):
        nonlocal count
        count += 1
        _record(log, m.group(0), placeholder)
        return placeholder

    return RE_IP.sub(repl, text), count


def sanitize_connection_strings(text, placeholder="Server=SERVER;", log=None):
    """Mask the Server= portion of connection strings."""
    count = 0

    def repl(m):
        nonlocal count
        count += 1
        _record(log, m.group(0), placeholder)
        return placeholder

    return RE_CONN_STRING.sub(repl, text), count


def sanitize_api_keys(text, placeholder="REDACTED", log=None):
    """apikey = 'abc123...'  ->  apikey = 'REDACTED'"""
    count = 0

    def repl(m):
        nonlocal count
        if m.group(2) == placeholder:
            return m.group(0)
        count += 1
        new = m.group(1) + placeholder
        _record(log, m.group(0), new)
        return new

    return RE_API_KEY.sub(repl, text), count


# Order matters: user-folder masking runs before generic path handling,
# specific patterns (keys, connection strings) before broad ones (URLs).
AUTO_SANITIZERS = {
    "api_keys": sanitize_api_keys,
    "connection_strings": sanitize_connection_strings,
    "windows_users": sanitize_windows_users,
    "network_paths": sanitize_network_paths,
    "local_paths": sanitize_local_paths,  # off by default, see DEFAULT_DISABLED
    "emails": sanitize_emails,
    "urls": sanitize_urls,
    "ip_addresses": sanitize_ips,
}

# Rules that only run if explicitly enabled in config.
DEFAULT_DISABLED = {"local_paths"}


def run_auto_sanitizers(text, config, changes=None):
    """
    Run all enabled auto-sanitizers over text.
    Returns (text, {rule_name: count}).
    If `changes` is a list, (rule, old, new) tuples are appended to it.
    """
    auto_cfg = config.get("auto_sanitize", {})
    safe_domains = set(d.lower() for d in config.get("safe_domains", []))
    safe_domains |= DEFAULT_SAFE_DOMAINS

    stats = {}

    for name, func in AUTO_SANITIZERS.items():
        rule = auto_cfg.get(name, {})
        default_enabled = name not in DEFAULT_DISABLED
        if not rule.get("enabled", default_enabled):
            continue

        kwargs = {}
        if "placeholder" in rule:
            kwargs["placeholder"] = rule["placeholder"]
        if name in ("emails", "urls"):
            kwargs["safe_domains"] = safe_domains

        log = [] if changes is not None else None
        text, count = func(text, log=log, **kwargs)

        if count:
            stats[name] = count
            if changes is not None:
                for old, new in log:
                    changes.append((name, old, new))

    return text, stats
