"""External threat intelligence reputation checking with SSRF protection and graceful fallback."""

import base64
import os
import requests
from dataclasses import dataclass
from typing import Optional
from .validators import is_safe_url_for_lookup


@dataclass
class ReputationResult:
    """Standardized threat intelligence report from external threat feeds."""
    is_configured: bool
    status: str  # "LOCAL_MODE", "CLEAN", "SUSPICIOUS", "MALICIOUS", "NOT_FOUND", "TIMEOUT", "RATE_LIMITED", "ERROR"
    provider: str
    malicious_count: int
    suspicious_count: int
    harmless_count: int
    total_engines: int
    permalink: Optional[str]
    summary: str
    disclaimer: str = (
        "Advisory Notice: Threat intelligence feeds index known malicious infrastructure. "
        "A zero-detection report does NOT guarantee that a URL is safe, as newly deployed "
        "phishing domains frequently evade threat feeds for the first 24-48 hours."
    )


class ReputationChecker:
    """Coordinates optional reputation lookups via VirusTotal or Google Safe Browsing."""

    def __init__(self):
        # Read API keys from environment only, never hardcoded
        self.vt_api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
        self.gsb_api_key = os.getenv("SAFEBROWSING_API_KEY", "").strip()
        self.timeout = 5.0  # Strict timeout in seconds

    def check_url(self, url: str) -> ReputationResult:
        """Perform external reputation check if an API key is configured and URL is SSRF-safe."""
        # 1. SSRF and URL safety verification
        is_safe, reason = is_safe_url_for_lookup(url)
        if not is_safe:
            return ReputationResult(
                is_configured=bool(self.vt_api_key or self.gsb_api_key),
                status="ERROR",
                provider="Internal Filter",
                malicious_count=0,
                suspicious_count=0,
                harmless_count=0,
                total_engines=0,
                permalink=None,
                summary=f"Lookup skipped: {reason}",
            )

        # 2. Check for configured provider
        if self.vt_api_key:
            return self._query_virustotal(url)
        elif self.gsb_api_key:
            return self._query_google_safe_browsing(url)
        else:
            return ReputationResult(
                is_configured=False,
                status="LOCAL_MODE",
                provider="None (Local Engine)",
                malicious_count=0,
                suspicious_count=0,
                harmless_count=0,
                total_engines=0,
                permalink=None,
                summary="Local Analysis Mode active. External threat intelligence API key not configured.",
            )

    def _query_virustotal(self, url: str) -> ReputationResult:
        """Query VirusTotal API v3 for URL analysis."""
        try:
            # VT v3 URL identifier is base64 of the URL without '=' padding
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            headers = {
                "x-apikey": self.vt_api_key,
                "Accept": "application/json",
                "User-Agent": "QRShield-AI-Scanner/1.0",
            }

            resp = requests.get(endpoint, headers=headers, timeout=self.timeout)

            if resp.status_code == 200:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0) + stats.get("undetected", 0)
                total = sum(stats.values()) if stats else 0

                permalink = f"https://www.virustotal.com/gui/url/{url_id}"

                if malicious >= 3:
                    status = "MALICIOUS"
                    summary = f"Flagged as Malicious by {malicious}/{total} security vendors on VirusTotal."
                elif malicious > 0 or suspicious >= 2:
                    status = "SUSPICIOUS"
                    summary = f"Flagged as Suspicious ({malicious} malicious, {suspicious} suspicious out of {total} vendors)."
                else:
                    status = "CLEAN"
                    summary = f"No security vendors flagged this URL on VirusTotal ({harmless}/{total} clean)."

                return ReputationResult(
                    is_configured=True,
                    status=status,
                    provider="VirusTotal API v3",
                    malicious_count=malicious,
                    suspicious_count=suspicious,
                    harmless_count=harmless,
                    total_engines=total,
                    permalink=permalink,
                    summary=summary,
                )

            elif resp.status_code == 404:
                return ReputationResult(
                    is_configured=True,
                    status="NOT_FOUND",
                    provider="VirusTotal API v3",
                    malicious_count=0,
                    suspicious_count=0,
                    harmless_count=0,
                    total_engines=0,
                    permalink=None,
                    summary="URL not previously scanned in VirusTotal database (New or Unindexed link).",
                )

            elif resp.status_code == 429:
                return ReputationResult(
                    is_configured=True,
                    status="RATE_LIMITED",
                    provider="VirusTotal API v3",
                    malicious_count=0,
                    suspicious_count=0,
                    harmless_count=0,
                    total_engines=0,
                    permalink=None,
                    summary="VirusTotal API rate limit reached. Proceeding with local heuristic analysis.",
                )

            else:
                return ReputationResult(
                    is_configured=True,
                    status="ERROR",
                    provider="VirusTotal API v3",
                    malicious_count=0,
                    suspicious_count=0,
                    harmless_count=0,
                    total_engines=0,
                    permalink=None,
                    summary=f"VirusTotal API responded with status code {resp.status_code}.",
                )

        except requests.Timeout:
            return ReputationResult(
                is_configured=True,
                status="TIMEOUT",
                provider="VirusTotal API v3",
                malicious_count=0,
                suspicious_count=0,
                harmless_count=0,
                total_engines=0,
                permalink=None,
                summary="VirusTotal lookup timed out. Relying on local heuristic analysis.",
            )
        except Exception as e:
            return ReputationResult(
                is_configured=True,
                status="ERROR",
                provider="VirusTotal API v3",
                malicious_count=0,
                suspicious_count=0,
                harmless_count=0,
                total_engines=0,
                permalink=None,
                summary=f"VirusTotal lookup error: {str(e)}",
            )

    def _query_google_safe_browsing(self, url: str) -> ReputationResult:
        """Query Google Safe Browsing API v4 for threat matches."""
        try:
            endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.gsb_api_key}"
            payload = {
                "client": {
                    "clientId": "qrshield-ai",
                    "clientVersion": "1.0",
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            }

            resp = requests.post(endpoint, json=payload, timeout=self.timeout)

            if resp.status_code == 200:
                data = resp.json()
                matches = data.get("matches", [])
                if matches:
                    threat_types = list({m.get("threatType", "THREAT") for m in matches})
                    return ReputationResult(
                        is_configured=True,
                        status="MALICIOUS",
                        provider="Google Safe Browsing v4",
                        malicious_count=len(matches),
                        suspicious_count=0,
                        harmless_count=0,
                        total_engines=1,
                        permalink=None,
                        summary=f"Google Safe Browsing detected threats: {', '.join(threat_types)}.",
                    )
                else:
                    return ReputationResult(
                        is_configured=True,
                        status="CLEAN",
                        provider="Google Safe Browsing v4",
                        malicious_count=0,
                        suspicious_count=0,
                        harmless_count=1,
                        total_engines=1,
                        permalink=None,
                        summary="No threat records found in Google Safe Browsing database.",
                    )
            elif resp.status_code == 429:
                return ReputationResult(
                    is_configured=True,
                    status="RATE_LIMITED",
                    provider="Google Safe Browsing v4",
                    malicious_count=0,
                    suspicious_count=0,
                    harmless_count=0,
                    total_engines=0,
                    permalink=None,
                    summary="Safe Browsing API rate limited.",
                )
            else:
                return ReputationResult(
                    is_configured=True,
                    status="ERROR",
                    provider="Google Safe Browsing v4",
                    malicious_count=0,
                    suspicious_count=0,
                    harmless_count=0,
                    total_engines=0,
                    permalink=None,
                    summary=f"Safe Browsing API returned status {resp.status_code}.",
                )

        except requests.Timeout:
            return ReputationResult(
                is_configured=True,
                status="TIMEOUT",
                provider="Google Safe Browsing v4",
                malicious_count=0,
                suspicious_count=0,
                harmless_count=0,
                total_engines=0,
                permalink=None,
                summary="Safe Browsing lookup timed out.",
            )
        except Exception as e:
            return ReputationResult(
                is_configured=True,
                status="ERROR",
                provider="Google Safe Browsing v4",
                malicious_count=0,
                suspicious_count=0,
                harmless_count=0,
                total_engines=0,
                permalink=None,
                summary=f"Safe Browsing error: {str(e)}",
            )
