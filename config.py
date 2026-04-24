import os

# Load from environment for security (recommended)
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "f9be6b631de6c89ca11824db80a89fab5d25b6051f92bde177c1b7aa92ac5d1c")

VT_BASE_URL = "https://www.virustotal.com/api/v3"

# Public API rate limit ≈ 4 requests/min
REQUEST_DELAY = 18  # seconds dlay