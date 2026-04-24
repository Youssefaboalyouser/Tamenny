import json
import time
import sys
from pathlib import Path
from typing import Dict, Any, List, Set

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import REQUEST_DELAY
from services.virustotal import scan_url, check_file_hash


INPUT_PATH = Path("data/parased/email.json")
OUTPUT_PATH = Path("data/results/virustotal.json")


def _load_json(file_path: Path) -> Dict[str, Any]:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        raise RuntimeError(f"Failed to load JSON: {e}")


def _save_json(file_path: Path, data: Dict[str, Any]) -> None:
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


def _extract_links(parsed: Dict[str, Any]) -> List[str]:
    links = parsed.get("links", [])
    if not isinstance(links, list):
        return []
    # Deduplicate
    return list(set(filter(None, links)))


def _extract_attachments(parsed: Dict[str, Any]) -> List[Dict[str, str]]:
    attachments = parsed.get("attachments", [])
    if not isinstance(attachments, list):
        return []

    cleaned = []
    seen_hashes: Set[str] = set()

    for att in attachments:
        sha256 = att.get("hash_sha256")
        filename = att.get("filename", "unknown")

        if not sha256 or sha256 in seen_hashes:
            continue

        seen_hashes.add(sha256)

        cleaned.append({
            "filename": filename,
            "hash_sha256": sha256
        })

    return cleaned


def run_virustotal_analysis() -> None:
    parsed = _load_json(INPUT_PATH)

    email_id = parsed.get("email_id", "unknown")

    links = _extract_links(parsed)
    attachments = _extract_attachments(parsed)

    vt_links_results = []
    vt_attachments_results = []

    error = None

    try:
        # Process links
        for idx, url in enumerate(links):
            result = scan_url(url)
            vt_links_results.append(result)

            if idx < len(links) - 1 or attachments:
                time.sleep(REQUEST_DELAY)

        # Process attachments
        for idx, att in enumerate(attachments):
            result = check_file_hash(
                att["hash_sha256"],
                att["filename"]
            )
            vt_attachments_results.append(result)

            if idx < len(attachments) - 1:
                time.sleep(REQUEST_DELAY)

    except Exception as e:
        error = str(e)

    final_output = {
        "email_id": email_id,
        "virustotal": {
            "links": vt_links_results,
            "attachments": vt_attachments_results,
            "error": error
        }
    }

    _save_json(OUTPUT_PATH, final_output)


if __name__ == "__main__":
    run_virustotal_analysis()