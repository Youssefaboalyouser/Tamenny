"""
email_parser.py
---------------
Parses .eml files into a rich, structured JSON format.

Supported email types:
  1. Plain-text
  2. HTML-only
  3. Multipart (plain + HTML)
  4. With attachments
  5. With inline images
  6. Forwarded
  7. Reply / thread
  8. Phishing / suspicious
  9. Newsletter / bulk marketing
"""

import email
import email.utils
import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from email import policy
from pathlib import Path
from typing import Optional
import io
import tempfile
import pytesseract
import cv2
import numpy as np
from PIL import Image
global is_image_email
# --------------------------------------------------------------------------- #
# Helper Functions                                                           #
# --------------------------------------------------------------------------- #
# These functions assist in decoding, parsing, and extracting data from email components.

# Image MIME types to target for OCR
IMAGE_MIME_TYPES = {"image/png", "image/jpeg", "image/jpg", "image/gif", "image/bmp", "image/tiff"}


def preprocess_for_ocr(image_bytes: bytes) -> np.ndarray:
    """
    Convert raw image bytes → preprocessed numpy array for Tesseract.
    Handles Arabic + English text via upscaling + Otsu thresholding.
    """
    # Decode bytes directly — no temp file needed
    nparr = np.frombuffer(image_bytes, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

    if img is None:
        raise ValueError("Could not decode image bytes")

    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    gray = cv2.resize(gray, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
    thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]
    return thresh


def ocr_image_bytes(image_bytes: bytes, lang: str = "ara+eng") -> str:
    """
    Run Tesseract OCR on raw image bytes.
    Returns extracted text string.
    """
    preprocessed = preprocess_for_ocr(image_bytes)
    config = r"--oem 3 --psm 3"
    text = pytesseract.image_to_string(preprocessed, lang=lang, config=config)
    return text.strip()


def save_image_attachment(image_bytes: bytes, filename: str, output_dir: str = "output/images") -> str:
    """
    Save image bytes to disk. Returns the saved file path.
    """
    from pathlib import Path
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    dest = out / filename
    dest.write_bytes(image_bytes)
    return str(dest)
# Function to decode bytes to string with multiple encoding fallbacks
def _safe_decode(payload: bytes, charset: str = "utf-8") -> str:
    """Decode bytes to str, falling back gracefully on encoding errors."""
    for enc in (charset or "utf-8", "utf-8", "latin-1"):
        try:
            return payload.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return payload.decode("utf-8", errors="replace")


# Function to decode RFC-2047 encoded email headers
def _decode_header_value(raw: Optional[str]) -> Optional[str]:
    """Decode RFC-2047 encoded header words into a plain string."""
    if raw is None:
        return None
    parts = email.header.decode_header(raw)
    decoded = []
    for fragment, charset in parts:
        # If charset is None, it means the fragment is already a string (not encoded)
        if isinstance(fragment, bytes):
            decoded.append(_safe_decode(fragment, charset))
        else:
            decoded.append(fragment)
    return "".join(decoded).strip() or None


# Function to parse email address strings into structured components
def _parse_address(raw: Optional[str]) -> dict:
    """
    Split 'Display Name <addr@host.com>' into structured fields.
    Returns {"name": ..., "email": ..., "domain": ...}.
    """
    if not raw:
        return {"name": None, "email": None, "domain": None}
    name, addr = email.utils.parseaddr(raw)
    name = name.strip() or None
    addr = addr.strip().lower() or None
    domain = addr.split("@", 1)[1] if addr and "@" in addr else None
    return {"name": name, "email": addr, "domain": domain}


# Function to normalize email timestamps to ISO-8601 UTC format
def _normalise_timestamp(raw: Optional[str]) -> Optional[str]:
    """Convert any RFC-2822 date string to ISO-8601 UTC."""
    if not raw:
        return None
    try:
        parsed = email.utils.parsedate_to_datetime(raw)
        utc = parsed.astimezone(timezone.utc)
        return utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return raw  # keep original if parsing fails


# Function to extract all HTTP/HTTPS URLs from text
def _extract_links(text: str) -> list[str]:
    """Pull all http/https URLs from a block of text."""
    return re.findall(r'https?://[^\s\'"<>]+', text)


# Function to compute MD5 and SHA256 hashes of binary data
def _hash_bytes(data: bytes) -> dict:
    return {
        "hash_md5":    hashlib.md5(data).hexdigest(),
        "hash_sha256": hashlib.sha256(data).hexdigest(),
    }


# Function to detect language based on script (simple heuristic for Arabic vs English)
def _detect_language(text: str) -> Optional[str]:
    """
    Lightweight heuristic: classify as 'ar' for Arabic script,
    otherwise default to 'en'.  Replace with langdetect for production.
    """
    if not text:
        return None
    arabic_chars = sum(1 for c in text if "\u0600" <= c <= "\u06ff")
    return "ar" if arabic_chars / max(len(text), 1) > 0.2 else "en"


# Function to extract authentication results (SPF, DKIM, DMARC) from email headers
def _extract_auth_result(headers: email.message.Message, keyword: str) -> Optional[str]:
    """
    Search Authentication-Results header for a specific mechanism result
    (spf, dkim, dmarc).  Returns 'pass', 'fail', 'neutral', etc., or None.
    """
    auth_results = headers.get_all("Authentication-Results") or []
    pattern = re.compile(rf"{keyword}=([a-zA-Z]+)", re.IGNORECASE)
    for header in auth_results:
        m = pattern.search(header)
        if m:
            return m.group(1).lower()
    return None


# Function to extract the originating IP address from Received headers
def _first_received_ip(headers: email.message.Message) -> Optional[str]:
    """Extract the IP address from the last (outermost) Received header."""
    received = headers.get_all("Received") or []
    ip_pattern = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")
    for header in received:
        m = ip_pattern.search(header)
        if m:
            return m.group(1)
    return None


# ---------------------------------------------------------------------------
# Core Email Parsing Function                                                #
# --------------------------------------------------------------------------- #
# This is the main function that parses an .eml file into a structured JSON dictionary.

def parse_eml(file_path: str | Path) -> dict:
    """
    Parse a .eml file and return a structured dictionary.

    Parameters
    ----------
    file_path : str or Path
        Path to the .eml file.

    Returns
    -------
    dict
        Rich email record following the standard schema.
    """
    # Convert input to Path object for consistency
    file_path = Path(file_path)
    # Read the entire .eml file as bytes
    raw_bytes = file_path.read_bytes()

    # Parse the email using Python's email library with a compatible policy
    msg: email.message.EmailMessage = email.message_from_bytes(
        raw_bytes, policy=policy.default
    )

    # Extract and parse sender and recipient information
    sender_raw   = _decode_header_value(msg.get("From"))
    reply_to_raw = _decode_header_value(msg.get("Reply-To"))
    sender       = _parse_address(sender_raw)
    reply_parsed = _parse_address(reply_to_raw)
    sender["reply_to"] = reply_parsed.get("email")   # Add reply-to email if present

    recipient = _decode_header_value(msg.get("To"))

    # Extract email body content (plain text, HTML) and attachments
    plain_text  = None
    html        = None
    attachments = []
    all_links   = []

    # Handle multipart emails by walking through each part
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))
            charset = part.get_content_charset()
            
            # Check if this part is an attachment
            if "attachment" in content_disposition or part.get_filename():
                filename = _decode_header_value(part.get_filename())
                payload  = part.get_payload(decode=True) or b""
                if filename:
                    attachment_record = {
                        "filename":    filename,
                        "type":        content_type,
                        **_hash_bytes(payload),  # Include hashes for integrity
                    }
                    if content_type in IMAGE_MIME_TYPES:
                        try:
                            ocr_text = ocr_image_bytes(payload)
                            attachment_record["ocr_text"] = ocr_text or None

                            # Optional: also save the image to disk
                            saved_path = save_image_attachment(payload, filename)
                            attachment_record["saved_path"] = saved_path

                        except Exception as exc:
                            attachment_record["ocr_error"] = str(exc)
                    attachments.append(attachment_record)
                continue
                

            # Extract plain text content
            if content_type == "text/plain":
                raw = part.get_payload(decode=True)
                if raw:
                    plain_text = _safe_decode(raw, charset)
                    all_links.extend(_extract_links(plain_text))

            # Extract HTML content
            elif content_type == "text/html":
                raw = part.get_payload(decode=True)
                if raw:
                    html = _safe_decode(raw, charset)
                    all_links.extend(_extract_links(html))
            if content_type in ("text/plain", "text/html"):
                if (html and "cid:" in html) or (plain_text and "cid:" in plain_text):
                    is_image_email = True
            # Inline images (Content-ID based, common in HTML emails)
            if content_type in IMAGE_MIME_TYPES and "inline" in content_disposition:
                payload = part.get_payload(decode=True) or b""
                filename = _decode_header_value(part.get_filename()) or f"inline_{uuid.uuid4().hex[:8]}.png"
                try:
                    ocr_text = ocr_image_bytes(payload)
                    attachments.append({
                        "filename":  filename,
                        "type":      content_type,
                        "inline":    True,
                        "ocr_text":  ocr_text or None,
                        **_hash_bytes(payload),
                    })
                except Exception as exc:
                    attachments.append({"filename": filename, "ocr_error": str(exc)})

    # Handle single-part emails
    else:
        raw = msg.get_payload(decode=True)
        if raw:
            content_type = msg.get_content_type()
            charset      = msg.get_content_charset()
            decoded      = _safe_decode(raw, charset)
            if content_type == "text/html":
                html = decoded
            else:
                plain_text = decoded
            all_links.extend(_extract_links(decoded))

    # Remove duplicate links while preserving order
    seen  = set()
    links = [u for u in all_links if not (u in seen or seen.add(u))]

    # Extract authentication and security-related headers
    headers_parsed = {
        "spf":              _extract_auth_result(msg, "spf"),
        "dkim":             _extract_auth_result(msg, "dkim"),
        "dmarc":            _extract_auth_result(msg, "dmarc"),
        "x_mailer":         _decode_header_value(msg.get("X-Mailer"))
                            or _decode_header_value(msg.get("User-Agent")),
        "received_from_ip": _first_received_ip(msg),
    }

    # Assemble the final structured email record
    return {
        "email_id":   str(uuid.uuid4()),  # Generate unique ID for this email
        "timestamp":  _normalise_timestamp(msg.get("Date")),
        "sender":     sender,
        "recipient":  recipient,
        "subject":    _decode_header_value(msg.get("Subject")),
        "body": {
            "plain_text": plain_text,
            "html":       html,
            "language":   _detect_language(plain_text or html or ""),  # Detect language of body text
        },
        "links":       links if links else None,  # Include links if any found
        "attachments": attachments if attachments else None,  # Include attachments if any
        "headers":     headers_parsed,
    }


# ---------------------------------------------------------------------------
# Batch Processing Function                                                  #
# --------------------------------------------------------------------------- #
# Processes multiple .eml files in a directory and outputs JSON files.

def parse_directory(input_dir: str | Path, output_dir: str | Path) -> None:
    # Ensure input and output are Path objects
    input_dir  = Path(input_dir)
    output_dir = Path(output_dir)
    # Create output directory if it doesn't exist
    output_dir.mkdir(parents=True, exist_ok=True)

    # Find all .eml files in the input directory
    eml_files = sorted(input_dir.glob("*.eml"))
    if not eml_files:
        print(f"No .eml files found in '{input_dir}'.")
        return

    results = []
    # Process each .eml file
    for eml_file in eml_files:
        print(f"  Parsing: {eml_file.name} ...", end=" ")
        try:
            data = parse_eml(eml_file)
            results.append(data)

            # Write individual JSON file for this email
            out_path = output_dir / eml_file.with_suffix(".json").name
            out_path.write_text(json.dumps(data, indent=4, ensure_ascii=False), encoding="utf-8")
            print("✔")
        except Exception as exc:
            print(f"✘  ({exc})")

    # Write a combined JSON file with all emails
    combined = output_dir / "all_emails.json"
    combined.write_text(json.dumps(results, indent=4, ensure_ascii=False), encoding="utf-8")
    print(f"\n  Combined output → {combined}")


# ---------------------------------------------------------------------------
# Command-Line Interface (CLI)                                               #
# --------------------------------------------------------------------------- #
# Entry point when the script is run from the command line.

if __name__ == "__main__":
    # Set up command-line argument parser
    import argparse

    cli = argparse.ArgumentParser(description="Parse .eml files to structured JSON.")
    cli.add_argument("input",  help="Path to a single .eml file or a directory of .eml files.")
    cli.add_argument("-o", "--output", default="output", help="Output directory (default: ./output)")
    args = cli.parse_args()

    # Determine input type and process accordingly
    src = Path(args.input)
    if src.is_dir():
        # If input is a directory, parse all .eml files in it
        parse_directory(src, args.output)
    elif src.is_file() and src.suffix == ".eml":
        # If input is a single .eml file, parse it and output JSON
        data = parse_eml(src)
        out_file = Path(args.output) / src.with_suffix(".json").name
        Path(args.output).mkdir(parents=True, exist_ok=True)
        out_file.write_text(json.dumps(data, indent=4, ensure_ascii=False), encoding="utf-8")
        print(json.dumps(data, indent=4, ensure_ascii=False))
        print(f"\n  Saved → {out_file}")
    else:
        print("Error: input must be a .eml file or a directory.")
"""
main
 ├── parse args
 ├── detect file
 ├── parse_eml
 │    ├── read bytes
 │    ├── build msg object
 │    ├── decode headers
 │    ├── parse sender
 │    ├── extract body
 │    │     ├── attachments
 │    │     ├── text
 │    │     ├── html
 │    │     └── links
 │    ├── analyze headers (spf/dkim)
 │    ├── normalize timestamp
 │    └── build JSON
 ├── save file
 └── print output
"""