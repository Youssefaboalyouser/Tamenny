import requests
import sys
from pathlib import Path
from typing import Dict, Any, Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import VIRUSTOTAL_API_KEY, VT_BASE_URL

HEADERS = {
    "x-apikey": VIRUSTOTAL_API_KEY
}


def _safe_get(data: dict, path: list, default=0):
    """
    Safely extract nested dictionary values.
    """
    try:
        for key in path:
            data = data[key]
        return data
    except (KeyError, TypeError):
        return default


def _compute_verdict(malicious_votes: int) -> str:
    """
    Apply verdict logic.
    """
    if malicious_votes >= 5:
        return "malicious"
    elif malicious_votes > 0:
        return "suspicious"
    return "clean"


def scan_url(url: str) -> Dict[str, Any]:
    """
    Submit URL and fetch analysis result.
    """
    result = {
        "url": url,
        "malicious_votes": 0,
        "clean_votes": 0,
        "verdict": "clean"
    }

    if not VIRUSTOTAL_API_KEY:
        result["error"] = "Missing API key"
        return result

    try:
        # Step 1: Submit URL
        submit_resp = requests.post(
            f"{VT_BASE_URL}/urls",
            headers=HEADERS,
            data={"url": url},
            timeout=15
        )

        if submit_resp.status_code == 429:
            raise Exception("Rate limit exceeded")

        submit_resp.raise_for_status()

        analysis_id = _safe_get(submit_resp.json(), ["data", "id"], None)

        if not analysis_id:
            raise Exception("Missing analysis ID")

        # Step 2: Get analysis
        analysis_resp = requests.get(
            f"{VT_BASE_URL}/analyses/{analysis_id}",
            headers=HEADERS,
            timeout=15
        )

        if analysis_resp.status_code == 429:
            raise Exception("Rate limit exceeded")

        analysis_resp.raise_for_status()

        stats = _safe_get(
            analysis_resp.json(),
            ["data", "attributes", "stats"],
            {}
        )

        malicious = stats.get("malicious", 0)
        harmless = stats.get("harmless", 0)

        result.update({
            "malicious_votes": malicious,
            "clean_votes": harmless,
            "verdict": _compute_verdict(malicious)
        })

    except requests.RequestException as e:
        result["error"] = f"Network error: {str(e)}"
    except Exception as e:
        result["error"] = str(e)

    return result


def check_file_hash(sha256: str, filename: str) -> Dict[str, Any]:
    """
    Check file reputation using hash.
    """
    result = {
        "filename": filename,
        "hash_sha256": sha256,
        "malicious_votes": 0,
        "clean_votes": 0,
        "verdict": "clean"
    }

    if not sha256:
        result["error"] = "Missing SHA256 hash"
        return result

    if not VIRUSTOTAL_API_KEY:
        result["error"] = "Missing API key"
        return result

    try:
        resp = requests.get(
            f"{VT_BASE_URL}/files/{sha256}",
            headers=HEADERS,
            timeout=15
        )

        if resp.status_code == 404:
            result["error"] = "Hash not found in VirusTotal"
            return result

        if resp.status_code == 429:
            raise Exception("Rate limit exceeded")

        resp.raise_for_status()

        stats = _safe_get(
            resp.json(),
            ["data", "attributes", "last_analysis_stats"],
            {}
        )

        malicious = stats.get("malicious", 0)
        harmless = stats.get("harmless", 0)

        result.update({
            "malicious_votes": malicious,
            "clean_votes": harmless,
            "verdict": _compute_verdict(malicious)
        })

    except requests.RequestException as e:
        result["error"] = f"Network error: {str(e)}"
    except Exception as e:
        result["error"] = str(e)

    return result