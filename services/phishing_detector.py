"""
Rule-Based Phishing Detection Engine
Senior Cybersecurity Engineer Implementation
"""

import json
import re
import socket
import ipaddress
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from html.parser import HTMLParser
from itertools import product as iterproduct
enable_network_check = False  # Set to True to enable reverse DNS and ASN checks (requires network access)

# ─────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────

TRUSTED_DOMAINS = [
    "paypal.com", "google.com", "microsoft.com", "apple.com", "amazon.com",
    "facebook.com", "twitter.com", "instagram.com", "linkedin.com", "netflix.com",
    "bank of america.com", "chase.com", "wellsfargo.com", "citibank.com",
    "ebay.com", "dropbox.com", "yahoo.com", "outlook.com", "hotmail.com",
    "dhl.com", "fedex.com", "ups.com", "usps.com", "irs.gov",
]

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
    "icloud.com", "protonmail.com", "mail.com", "yandex.com", "zoho.com",
    "live.com", "msn.com", "gmx.com", "inbox.com",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "short.io", "cutt.ly", "rb.gy",
    "shorturl.at", "tiny.cc", "bl.ink",
}

HIGH_RISK_EXTENSIONS = {
    ".exe", ".js", ".vbs", ".scr", ".bat", ".cmd", ".docm", ".xlsm",
    ".msi", ".ps1", ".hta", ".jar", ".pif", ".com", ".reg",
}

MIME_EXTENSION_MAP = {
    "application/pdf": ".pdf",
    "application/msword": ".doc",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.ms-excel": ".xls",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/zip": ".zip",
    "application/x-rar-compressed": ".rar",
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "text/plain": ".txt",
    "application/x-msdownload": ".exe",
}

CHAR_SUBSTITUTIONS = {
    "0": "o", "1": "l", "3": "e", "4": "a",
    "5": "s", "6": "g", "7": "t", "@": "a",
    "vv": "w", "rn": "m",
}

SUSPICIOUS_ASN_KEYWORDS = [
    "digitalocean", "linode", "vultr", "ovh", "hetzner",
    "choopa", "psychz", "serverius", "hostwinds", "contabo",
    "frantech", "buyvm", "sharktech", "m247",
]


# ─────────────────────────────────────────────
# HELPER UTILITIES
# ─────────────────────────────────────────────

def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


def normalize_domain(domain: str) -> str:
    """Normalize domain by applying known character substitutions."""
    normalized = domain.lower()
    for fake, real in CHAR_SUBSTITUTIONS.items():
        normalized = normalized.replace(fake, real)
    return normalized


def extract_domain(url_or_email: str) -> str:
    """Extract bare domain from a URL or email address."""
    if not url_or_email:
        return ""
    if url_or_email.startswith("http"):
        parsed = urlparse(url_or_email)
        return parsed.netloc.lower().lstrip("www.")
    if "@" in url_or_email:
        return url_or_email.split("@")[-1].lower()
    return url_or_email.lower().lstrip("www.")


def is_ip_address(host: str) -> bool:
    """Check if host string is an IP address."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def reverse_dns_lookup(ip: str) -> str | None:
    """Attempt reverse DNS lookup; return hostname or None."""
    try:
        result = socket.gethostbyaddr(ip)
        return result[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def get_asn_info(ip: str) -> str | None:
    """
    Attempt to get ASN/org info via a local whois-style approach.
    In production, use an IP intelligence API.
    Returns a description string or None.
    """
    try:
        import subprocess
        result = subprocess.run(
            ["whois", ip], capture_output=True, text=True, timeout=5
        )
        output = result.stdout.lower()
        for keyword in SUSPICIOUS_ASN_KEYWORDS:
            if keyword in output:
                return keyword
        return None
    except Exception:
        return None


# ─────────────────────────────────────────────
# HTML PARSER
# ─────────────────────────────────────────────

class PhishingHTMLParser(HTMLParser):
    """Custom HTML parser for phishing indicator extraction."""

    def __init__(self):
        super().__init__()
        self.anchor_pairs = []          # (visible_text, href)
        self._current_href = None
        self._current_text = []
        self.raw_styles = []            # all inline style values
        self.has_base64_images = False
        self._style_count = 0

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        style = attrs_dict.get("style", "")
        if style:
            self.raw_styles.append(style)
            self._style_count += 1

        if tag == "a":
            self._current_href = attrs_dict.get("href", "")
            self._current_text = []

        if tag == "img":
            src = attrs_dict.get("src", "")
            if src.startswith("data:image"):
                self.has_base64_images = True

    def handle_endtag(self, tag):
        if tag == "a" and self._current_href is not None:
            visible_text = "".join(self._current_text).strip()
            self.anchor_pairs.append((visible_text, self._current_href))
            self._current_href = None
            self._current_text = []

    def handle_data(self, data):
        if self._current_href is not None:
            self._current_text.append(data)

    @property
    def inline_style_count(self):
        return self._style_count


# ─────────────────────────────────────────────
# DETECTION MODULES
# ─────────────────────────────────────────────

def auth_checks(email: dict) -> list[str]:
    """
    Rule 1: Email Authentication Analysis (SPF, DKIM, DMARC).
    """
    flags = []
    headers = email.get("headers", {})

    spf = (headers.get("spf") or "").lower()
    dkim = (headers.get("dkim") or "").lower()
    dmarc = (headers.get("dmarc") or "").lower()

    if spf == "fail":
        flags.append("SPF failed")
    elif spf == "none":
        flags.append("SPF missing")

    if dkim == "fail":
        flags.append("DKIM failed")

    if dmarc == "fail":
        flags.append("DMARC failed")

    if dkim == "pass" and dmarc == "fail":
        flags.append("Authentication misalignment (DKIM pass, DMARC fail)")

    return flags


def sender_checks(email: dict) -> list[str]:
    """
    Rule 2: Sender Identity & Domain Analysis.
    """
    flags = []
    sender = email.get("sender", {})
    sender_email = sender.get("email", "")
    sender_domain = sender.get("domain", "") or extract_domain(sender_email)
    reply_to = sender.get("reply_to", "")
    links = email.get("links", [])
    sender_name = sender.get("name", "")

    # A) Domain mismatch — reply-to
    if reply_to:
        reply_domain = extract_domain(reply_to)
        if reply_domain and reply_domain != sender_domain:
            flags.append("Reply-To domain mismatch")

    # A) Domain mismatch — links
    link_domains = {extract_domain(url) for url in links if url}
    if link_domains and sender_domain and sender_domain not in link_domains:
        flags.append("Sender domain does not match link domains")

    # B) Lookalike / typosquatting
    normalized_sender = normalize_domain(sender_domain)
    for trusted in TRUSTED_DOMAINS:
        trusted_base = trusted.split(".")[0]
        sender_base = normalized_sender.split(".")[0]
        dist = levenshtein_distance(sender_base, trusted_base)
        if dist == 1 and len(sender_base) > 4 and sender_domain != trusted:
            flags.append(f"Possible typosquatting domain detected ({sender_domain})")
            break

    # C) Free email for organizational use
    if sender_domain in FREE_EMAIL_PROVIDERS:
        # Heuristic: if sender name looks corporate (contains Inc, Support, etc.)
        org_keywords = ["support", "noreply", "service", "info", "admin",
                        "helpdesk", "security", "billing", "account", "team"]
        name_lower = sender_name.lower()
        local_part = sender_email.split("@")[0].lower() if "@" in sender_email else ""
        if any(kw in name_lower or kw in local_part for kw in org_keywords):
            flags.append("Free email used for organizational communication")

    return flags


def link_checks(email: dict, vt_data: dict | None = None) -> list[str]:
    """
    Rule 3: Link Analysis.
    """
    flags = []
    links = email.get("links", [])
    html_body = email.get("body", {}).get("html", "") or ""

    # Build VT lookup map
    vt_links = {}
    if vt_data:
        for entry in vt_data.get("virustotal", {}).get("links", []):
            vt_links[entry.get("url")] = entry

    # Parse HTML for anchor text mismatches
    parser = PhishingHTMLParser()
    if html_body:
        parser.feed(html_body)

    seen_flags = set()

    for url in links:
        parsed = urlparse(url)
        host = parsed.netloc
        query_params = parse_qs(parsed.query)

        # A) VirusTotal verdict
        if url in vt_links:
            vt_entry = vt_links[url]
            if vt_entry.get("verdict") != "clean":
                flag = "Malicious link detected by VirusTotal"
                if flag not in seen_flags:
                    flags.append(flag)
                    seen_flags.add(flag)
            total_votes = (vt_entry.get("malicious_votes", 0) +
                           vt_entry.get("clean_votes", 0))
            if total_votes == 0:
                flag = "Unverified link (no reputation data)"
                if flag not in seen_flags:
                    flags.append(flag)
                    seen_flags.add(flag)
        else:
            flag = "Unverified link (no reputation data)"
            if flag not in seen_flags:
                flags.append(flag)
                seen_flags.add(flag)

        # B) URL structure — IP address
        clean_host = host.split(":")[0]  # strip port
        if is_ip_address(clean_host):
            flag = "Suspicious URL (IP address used)"
            if flag not in seen_flags:
                flags.append(flag)
                seen_flags.add(flag)

        # B) Excessively long URL
        if len(url) > 100:
            flag = "Suspicious long URL"
            if flag not in seen_flags:
                flags.append(flag)
                seen_flags.add(flag)

        # B) Many URL parameters
        if len(query_params) > 5:
            flag = "Suspicious URL parameters"
            if flag not in seen_flags:
                flags.append(flag)
                seen_flags.add(flag)

        # B) URL shortener
        bare_host = clean_host.lstrip("www.")
        if bare_host in URL_SHORTENERS:
            flag = "URL shortener used"
            if flag not in seen_flags:
                flags.append(flag)
                seen_flags.add(flag)

    # C) Anchor text mismatch
    for visible_text, href in parser.anchor_pairs:
        if not href or not visible_text:
            continue
        if href.startswith("http"):
            href_domain = extract_domain(href)
            # Check if visible text looks like a URL
            text_url_match = re.search(r"https?://([^\s/]+)", visible_text)
            if text_url_match:
                text_domain = text_url_match.group(1).lstrip("www.")
                if text_domain and text_domain != href_domain:
                    flag = "Anchor text mismatch detected"
                    if flag not in seen_flags:
                        flags.append(flag)
                        seen_flags.add(flag)

    return flags


def attachment_checks(email: dict, vt_data: dict | None = None) -> list[str]:
    """
    Rule 4: Attachment Analysis.
    """
    flags = []
    attachments = email.get("attachments", [])

    # Build VT attachment lookup by sha256
    vt_attachments = {}
    if vt_data:
        for entry in vt_data.get("virustotal", {}).get("attachments", []):
            vt_attachments[entry.get("hash_sha256")] = entry

    for att in attachments:
        filename = att.get("filename", "")
        mime_type = att.get("type", "")
        sha256 = att.get("hash_sha256", "")

        ext = Path(filename).suffix.lower() if filename else ""

        # A) High-risk extension
        if ext in HIGH_RISK_EXTENSIONS:
            flags.append(f"High-risk attachment type ({ext})")

        # B) MIME mismatch
        expected_ext = MIME_EXTENSION_MAP.get(mime_type)
        if expected_ext and ext and ext != expected_ext:
            flags.append(
                f"Attachment type mismatch ({filename}: extension {ext} "
                f"but MIME {mime_type})"
            )

        # C) VirusTotal
        if sha256 and sha256 in vt_attachments:
            vt_entry = vt_attachments[sha256]
            if vt_entry.get("malicious_votes", 0) > 0:
                flags.append(f"Malicious attachment detected by VirusTotal ({filename})")
        elif sha256:
            flags.append(f"Attachment not found in VirusTotal ({filename})")

    return flags


def header_checks(email: dict) -> list[str]:
    """
    Rule 5: Header-Level Forensics (Reverse DNS, ASN, Geo).
    """
    flags = []
    headers = email.get("headers", {})
    ip = headers.get("received_from_ip", "")

    if not ip:
        return flags

    # A) Reverse DNS
    hostname = None
    if enable_network_check == True:
        hostname = reverse_dns_lookup(ip)
    if not hostname:
        flags.append("Missing reverse DNS")

    # B) ASN / IP reputation
    asn_info = None
    if enable_network_check == True:
        asn_info = get_asn_info(ip)
    if asn_info:
        flags.append(f"Suspicious sending infrastructure (ASN: {asn_info})")

    # C) Geographical mismatch (heuristic via hostname TLD)
    sender_domain = email.get("sender", {}).get("domain", "")
    if hostname and sender_domain:
        sender_tld = sender_domain.split(".")[-1].lower()
        hostname_tld = hostname.split(".")[-1].lower()
        # If both have country-code TLDs and they differ
        if (
            len(sender_tld) == 2 and len(hostname_tld) == 2
            and sender_tld != hostname_tld
            and sender_tld not in ("com", "net", "org")
            and hostname_tld not in ("com", "net", "org")
        ):
            flags.append("Geographical mismatch between sender and infrastructure")

    return flags


def html_checks(email: dict) -> list[str]:
    """
    Rule 6: HTML Structure Tricks.
    """
    flags = []
    html_body = email.get("body", {}).get("html", "") or ""

    if not html_body:
        return flags

    # Hidden text patterns
    hidden_patterns = [
        r"display\s*:\s*none",
        r"visibility\s*:\s*hidden",
    ]
    for pattern in hidden_patterns:
        if re.search(pattern, html_body, re.IGNORECASE):
            flags.append("Hidden text detected in HTML")
            break

    # Zero-size text
    if re.search(r"font-size\s*:\s*0", html_body, re.IGNORECASE):
        flags.append("Zero-size text detected")

    # Base64 embedded images
    if re.search(r'src\s*=\s*["\']data:image/', html_body, re.IGNORECASE):
        flags.append("Embedded base64 image detected")

    # Excessive inline styling / obfuscation heuristic
    parser = PhishingHTMLParser()
    parser.feed(html_body)
    if parser.inline_style_count > 20:
        flags.append("Excessive HTML styling (possible obfuscation)")

    return flags


# ─────────────────────────────────────────────
# MAIN ENGINE
# ─────────────────────────────────────────────

def analyze_email(email: dict, vt_data: dict | None = None) -> dict:
    """
    Run all rule-based checks and return structured JSON output.
    """
    all_flags = []

    all_flags.extend(auth_checks(email))
    all_flags.extend(sender_checks(email))
    all_flags.extend(link_checks(email, vt_data))
    all_flags.extend(attachment_checks(email, vt_data))
    all_flags.extend(header_checks(email))
    all_flags.extend(html_checks(email))

    # Deduplicate while preserving order
    seen = set()
    unique_flags = []
    for flag in all_flags:
        if flag not in seen:
            unique_flags.append(flag)
            seen.add(flag)

    return {
        "email_id": email.get("email_id", ""),
        "rule_based": {
            "flags": unique_flags
        }
    }


# ─────────────────────────────────────────────
# FILE I/O HELPERS
# ─────────────────────────────────────────────

def load_json(path: str) -> dict | None:
    """Load a JSON file safely."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[WARNING] Could not load {path}: {e}")
        return None


def process_directory(parsed_dir: str, result_dir: str, output_dir: str):
    """
    Process all parsed email JSON files in parsed_dir,
    optionally merging VirusTotal results from result_dir,
    writing output to output_dir.
    """
    parsed_path = Path(parsed_dir)
    result_path = Path(result_dir)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    email_files = list(parsed_path.glob("*.json"))
    if not email_files:
        print(f"[INFO] No JSON files found in {parsed_dir}")
        return

    for email_file in email_files:
        email_data = load_json(str(email_file))
        if not email_data:
            continue

        email_id = email_data.get("email_id", email_file.stem)

        # Try to load matching VT result
        vt_file = result_path / email_file.name
        vt_data = load_json(str(vt_file)) if vt_file.exists() else None

        result = analyze_email(email_data, vt_data)

        out_file = output_path / f"{email_id}_flags.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)

        print(f"[OK] {email_file.name} → {out_file.name} "
              f"({len(result['rule_based']['flags'])} flags)")

