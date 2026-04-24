import os

# Load from environment for security (recommended)
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

if not VIRUSTOTAL_API_KEY:
    raise ValueError("API key not found in environment variables")

VT_BASE_URL = "https://www.virustotal.com/api/v3"

# Public API rate limit ≈ 4 requests/min
REQUEST_DELAY = 18  # seconds dlay