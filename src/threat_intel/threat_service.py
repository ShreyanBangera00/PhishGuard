"""
Threat Intelligence Service for PhishGuard.
Integrates with Google Safe Browsing API to cross-reference URLs against
continuously updated threat databases.

The service is designed to be gracefully optional — if no API key is
configured, the system falls back to ML-only detection with no errors.
"""

import logging
import requests

logger = logging.getLogger(__name__)


class GoogleSafeBrowsingClient:
    """Client for Google Safe Browsing Lookup API v4.

    Checks URLs against Google's constantly-updated database of phishing,
    malware, and unwanted software threats.

    Setup:
        1. Go to https://console.cloud.google.com/
        2. Create a project and enable "Safe Browsing API"
        3. Create an API key under Credentials
        4. Set GOOGLE_SAFE_BROWSING_API_KEY in your .env file
    """

    API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    THREAT_TYPES = [
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION",
    ]

    def __init__(self, api_key: str = None):
        if api_key and api_key != "YOUR_API_KEY_HERE":
            self.api_key = api_key
            logger.info("[PhishGuard] Google Safe Browsing API configured.")
        else:
            self.api_key = None
            logger.warning(
                "[PhishGuard] Google Safe Browsing API key not configured. "
                "Threat intelligence lookups will be unavailable. "
                "Set GOOGLE_SAFE_BROWSING_API_KEY in your .env file."
            )

    @property
    def is_configured(self) -> bool:
        return self.api_key is not None

    def check_url(self, url: str) -> dict:
        """Check a URL against Google Safe Browsing.

        Args:
            url: The URL to check.

        Returns:
            Dictionary with keys:
                - source: 'google_safe_browsing'
                - available: bool (whether the check was performed)
                - is_threat: bool (True if URL is flagged)
                - threat_types: list of matched threat type strings
                - reason: str (error message if unavailable)
        """
        if not self.api_key:
            return {
                "source": "google_safe_browsing",
                "available": False,
                "is_threat": False,
                "threat_types": [],
                "reason": "API key not configured",
            }

        request_body = {
            "client": {
                "clientId": "phishguard",
                "clientVersion": "1.0.0",
            },
            "threatInfo": {
                "threatTypes": self.THREAT_TYPES,
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        try:
            response = requests.post(
                f"{self.API_URL}?key={self.api_key}",
                json=request_body,
                timeout=5,
            )
            response.raise_for_status()
            data = response.json()

            matches = data.get("matches", [])
            if matches:
                threat_types = list(set(m.get("threatType", "") for m in matches))
                return {
                    "source": "google_safe_browsing",
                    "available": True,
                    "is_threat": True,
                    "threat_types": threat_types,
                }
            else:
                return {
                    "source": "google_safe_browsing",
                    "available": True,
                    "is_threat": False,
                    "threat_types": [],
                }

        except requests.exceptions.Timeout:
            logger.warning("[PhishGuard] Google Safe Browsing request timed out.")
            return {
                "source": "google_safe_browsing",
                "available": False,
                "is_threat": False,
                "threat_types": [],
                "reason": "Request timed out",
            }
        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if e.response is not None else "unknown"
            logger.error(f"[PhishGuard] Google Safe Browsing HTTP error: {status}")
            return {
                "source": "google_safe_browsing",
                "available": False,
                "is_threat": False,
                "threat_types": [],
                "reason": f"HTTP error {status}",
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"[PhishGuard] Google Safe Browsing network error: {e}")
            return {
                "source": "google_safe_browsing",
                "available": False,
                "is_threat": False,
                "threat_types": [],
                "reason": f"Network error: {str(e)}",
            }


class ThreatIntelligenceService:
    """Unified threat intelligence service.

    Aggregates results from all configured threat intelligence providers.
    Currently supports:
        - Google Safe Browsing (primary)

    The service is designed to degrade gracefully — unconfigured or
    unreachable providers simply return 'available: False' without
    raising exceptions.
    """

    def __init__(self, safe_browsing_api_key: str = None):
        self.gsb_client = GoogleSafeBrowsingClient(api_key=safe_browsing_api_key)

    def lookup_url(self, url: str) -> dict:
        """Cross-reference a URL against all configured threat intelligence sources.

        Args:
            url: The URL to check.

        Returns:
            Dictionary with:
                - url: the checked URL
                - any_threat_found: bool
                - google_safe_browsing: dict with check results
        """
        gsb_result = self.gsb_client.check_url(url)

        any_threat = gsb_result.get("is_threat", False)

        return {
            "url": url,
            "any_threat_found": any_threat,
            "google_safe_browsing": gsb_result,
        }
