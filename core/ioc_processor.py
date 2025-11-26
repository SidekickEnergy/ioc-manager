# core/ioc_processor.py

import re

# Ordered list of IoC type patterns from most specific to more general
IOC_TYPES = [
    ("ipv6", re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b")),
    ("ipv4", re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("md5", re.compile(r"\b[a-fA-F\d]{32}\b")),
    ("sha1", re.compile(r"\b[a-fA-F\d]{40}\b")),
    ("sha256", re.compile(r"\b[a-fA-F\d]{64}\b")),
    ("url", re.compile(r"\bhttps?://[^\s]+", re.IGNORECASE)),
    ("hostname", re.compile(r"\b(?:(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})\b")),
    ("domain", re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)),
]

def detect_ioc_type(ioc: str) -> str:
    """Detect the type of IoC based on regex patterns."""
    stripped_ioc = ioc.strip().lower()

    for ioc_type, pattern in IOC_TYPES:
        if pattern.fullmatch(stripped_ioc):
            return ioc_type
    # Example logic if needed in detect_ioc_type
    if ioc_type == "hostname":
        return "domain"  # Only if you want to collapse hostname to domain


    # Fallback: if starts with www., it's very likely a domain
    if stripped_ioc.startswith("www."):
        return "domain"

    return "unknown"

def normalize_ioc(ioc: str) -> str:
    """Normalize the IoC (lowercase, strip params, etc.)."""
    return ioc.strip().lower()

def deduplicate_iocs(iocs: list) -> list:
    """Remove duplicate IoCs."""
    return list(set(iocs))

def process_iocs(ioc_list: list) -> list:
    """Run full processing on a list of IoCs."""
    normalized = [normalize_ioc(ioc) for ioc in ioc_list]
    deduped = deduplicate_iocs(normalized)

    processed = []
    for ioc in deduped:
        ioc_type = detect_ioc_type(ioc)
        processed.append({
            "ioc": ioc,
            "type": ioc_type
        })
    return processed
