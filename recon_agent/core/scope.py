from __future__ import annotations

import fnmatch
import re
from urllib.parse import urlparse


def _extract_domain(target: str) -> str:
    """Extract the domain/host from a URL or return as-is if already a domain."""
    if "://" in target:
        parsed = urlparse(target)
        return parsed.netloc.split(":")[0].lower()
    return target.lower().split(":")[0].split("/")[0]


def _matches_pattern(host: str, pattern: str) -> bool:
    """Check if host matches a scope pattern (supports wildcards)."""
    pattern = pattern.lower().strip()
    host = host.lower().strip()

    if pattern.startswith("*."):
        suffix = pattern[2:]
        return host == suffix or host.endswith("." + suffix)

    return fnmatch.fnmatch(host, pattern)


def is_in_scope(target: str, in_scope: list[str], out_of_scope: list[str]) -> bool:
    """Return True if target is in scope and not explicitly out of scope."""
    host = _extract_domain(target)

    # Check out-of-scope first (deny wins)
    for pattern in out_of_scope:
        if _matches_pattern(host, pattern):
            return False

    for pattern in in_scope:
        if _matches_pattern(host, pattern):
            return True

    return False


def normalize_scope_entry(entry: str) -> str:
    """Normalize a scope entry to a consistent format."""
    entry = entry.strip()
    if "://" in entry:
        parsed = urlparse(entry)
        return parsed.netloc.split(":")[0].lower()
    return entry.lower()


def parse_scope_list(raw: str) -> list[str]:
    """Parse a comma/newline separated list of scope entries."""
    entries = re.split(r"[,\n]+", raw)
    result = []
    for e in entries:
        e = e.strip()
        if e:
            result.append(normalize_scope_entry(e))
    return result
