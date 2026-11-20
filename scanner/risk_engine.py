"""Weighted, transparent risk scoring engine for QRShield AI."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any
from .url_analyzer import SecurityIndicator, URLAnalysisResult
from .decoder import ContentType, QRScanResult


class RiskLevel(str, Enum):
    """Risk tiers according to standard cybersecurity categorization."""
    LOW = "Low Risk"
    MODERATE = "Moderate Risk"
    HIGH = "High Risk"
    CRITICAL = "Critical Risk"


@dataclass
class RiskBreakdownItem:
    """Individual indicator's contribution to the total risk score."""
    indicator_id: str
    title: str
    severity: str
    points: int
    category: str


@dataclass
class RiskAssessment:
    """Consolidated risk assessment result for a scanned QR payload."""
    score: int  # 0 to 100
    level: RiskLevel
    color_hex: str
    badge_style: str
    summary: str
    action_recommendation: str
    breakdown: List[RiskBreakdownItem] = field(default_factory=list)
    indicators: List[SecurityIndicator] = field(default_factory=list)
    synergy_penalty: int = 0


class RiskEngine:
    """Calculates deterministic, modular risk scores for URLs and non-URL payloads."""

    # Weights by severity
    SEVERITY_WEIGHTS: Dict[str, int] = {
        "CRITICAL": 35,
        "HIGH": 25,
        "MEDIUM": 15,
        "LOW": 8,
    }

    # Custom indicator overrides where specific threats demand calibrated weighting
    INDICATOR_WEIGHT_OVERRIDES: Dict[str, int] = {
        "AT_SYMBOL_TRICK": 40,
        "SUSPICIOUS_EXTENSION": 35,
        "IP_ADDRESS_HOST": 30,
        "HOMOGRAPH_TYPOSQUATTING": 28,
        "PUNYCODE_DOMAIN": 25,
        "URL_SHORTENER": 25,
        "OBFUSCATED_PATTERNS": 25,
        "UNUSUAL_PORT": 22,
        "MISLEADING_HOSTNAME": 22,
        "HTTP_INSECURE": 15,
        "SUSPICIOUS_KEYWORDS": 15,
        "EMBEDDED_REDIRECT": 15,
        "EXCESSIVE_SUBDOMAINS": 12,
        "SUSPICIOUS_LENGTH": 8,
    }

    def assess_url(self, analysis: URLAnalysisResult) -> RiskAssessment:
        """Calculate the risk score and actionable advisory for a URL."""
        if not analysis.is_valid:
            return RiskAssessment(
                score=50,
                level=RiskLevel.MODERATE,
                color_hex="#FFB703",
                badge_style="warning",
                summary="URL syntax could not be completely parsed or validated.",
                action_recommendation="Do not proceed with unparseable or malformed URLs.",
                breakdown=[],
                indicators=[],
            )

        breakdown: List[RiskBreakdownItem] = []
        raw_score = 0
        detected_ids = set()

        for ind in analysis.indicators:
            detected_ids.add(ind.id)
            weight = self.INDICATOR_WEIGHT_OVERRIDES.get(ind.id, self.SEVERITY_WEIGHTS.get(ind.severity, 10))
            raw_score += weight
            breakdown.append(
                RiskBreakdownItem(
                    indicator_id=ind.id,
                    title=ind.title,
                    severity=ind.severity,
                    points=weight,
                    category=ind.category,
                )
            )

        # Compound Threat Synergy Bonus:
        # Threat actors deliberately combine (HTTP + IP + Keywords) or (Typosquatting + Keywords)
        synergy_penalty = 0
        if "HTTP_INSECURE" in detected_ids and "IP_ADDRESS_HOST" in detected_ids:
            synergy_penalty += 15
        if "SUSPICIOUS_KEYWORDS" in detected_ids and ("IP_ADDRESS_HOST" in detected_ids or "HOMOGRAPH_TYPOSQUATTING" in detected_ids or "PUNYCODE_DOMAIN" in detected_ids):
            synergy_penalty += 15
        if "URL_SHORTENER" in detected_ids and "SUSPICIOUS_KEYWORDS" in detected_ids:
            synergy_penalty += 10

        total_score = min(100, max(0, raw_score + synergy_penalty))

        # Categorize
        level, color_hex, badge_style, summary, action = self._classify_score(total_score, len(analysis.indicators))

        return RiskAssessment(
            score=total_score,
            level=level,
            color_hex=color_hex,
            badge_style=badge_style,
            summary=summary,
            action_recommendation=action,
            breakdown=breakdown,
            indicators=analysis.indicators,
            synergy_penalty=synergy_penalty,
        )

    def assess_non_url(self, qr_result: QRScanResult) -> RiskAssessment:
        """Calculate risk assessment for non-URL payloads (Wi-Fi, vCard, Plain Text, SMS, etc.)."""
        ctype = qr_result.content_type
        score = 0
        breakdown: List[RiskBreakdownItem] = []
        indicators: List[SecurityIndicator] = []

        if ctype == ContentType.WIFI:
            # Check for unencrypted open Wi-Fi
            details = qr_result.details or {}
            sec_type = details.get("security_type", "").upper()
            has_pwd = details.get("has_password", False)

            if sec_type in ("NOPASS", "NONE", "OPEN") or not has_pwd:
                score = 35
                ind = SecurityIndicator(
                    id="OPEN_WIFI",
                    title="Unencrypted Open Wi-Fi Network",
                    severity="MEDIUM",
                    category="Wireless Security",
                    description="This QR code configures a wireless connection without password encryption. Open Wi-Fi networks allow anyone in proximity to eavesdrop on unencrypted network packets.",
                    evidence=f"SSID: '{details.get('ssid')}', Security: {sec_type}",
                    recommendation="Avoid connecting automatically to unencrypted public Wi-Fi networks.",
                )
                indicators.append(ind)
                breakdown.append(RiskBreakdownItem(
                    indicator_id=ind.id,
                    title=ind.title,
                    severity=ind.severity,
                    points=35,
                    category=ind.category,
                ))
            else:
                score = 10  # Protected Wi-Fi, low risk

        elif ctype in (ContentType.PHONE, ContentType.SMS):
            score = 15  # Potential premium SMS / toll fraud if unexpected
            ind = SecurityIndicator(
                id="AUTOMATED_DIAL_OR_SMS",
                title="Automated Call / SMS Trigger",
                severity="LOW",
                category="Device Action",
                description="Scanning this QR code prompts your mobile device to initiate an SMS or phone call. Attackers sometimes deploy malicious QR stickers on parking meters to trigger premium-rate SMS billing.",
                evidence=f"Payload type: {ctype.value}",
                recommendation="Verify the recipient number before confirming any call or text message.",
            )
            indicators.append(ind)
            breakdown.append(RiskBreakdownItem(
                indicator_id=ind.id,
                title=ind.title,
                severity=ind.severity,
                points=15,
                category=ind.category,
            ))

        elif ctype == ContentType.VCARD:
            score = 5  # Standard contact card, low risk

        elif ctype == ContentType.PLAIN_TEXT:
            # Check if plain text contains shell-like commands or injection patterns
            raw_text = qr_result.raw_content
            if any(term in raw_text.lower() for term in ["cmd.exe", "powershell", "curl http", "wget http", "rm -rf", "eval("]):
                score = 65
                ind = SecurityIndicator(
                    id="SUSPICIOUS_COMMAND_PAYLOAD",
                    title="Suspicious Shell/Script Tokens in Text",
                    severity="HIGH",
                    category="Command Injection",
                    description="Decoded plain text payload contains command-line syntax or scripting execution keywords.",
                    evidence=raw_text[:80],
                    recommendation="Do not paste or execute these commands in any terminal or command prompt.",
                )
                indicators.append(ind)
                breakdown.append(RiskBreakdownItem(
                    indicator_id=ind.id,
                    title=ind.title,
                    severity=ind.severity,
                    points=65,
                    category=ind.category,
                ))
            else:
                score = 0

        else:
            score = 10

        level, color_hex, badge_style, summary, action = self._classify_score(score, len(indicators))

        return RiskAssessment(
            score=score,
            level=level,
            color_hex=color_hex,
            badge_style=badge_style,
            summary=summary,
            action_recommendation=action,
            breakdown=breakdown,
            indicators=indicators,
            synergy_penalty=0,
        )

    def _classify_score(self, score: int, indicator_count: int) -> tuple[RiskLevel, str, str, str, str]:
        """Map numerical score (0-100) to standard RiskLevel, UI colors, and actionable guidelines."""
        if score < 25:
            return (
                RiskLevel.LOW,
                "#06D6A0",  # Cyber Emerald Green
                "success",
                "No significant security threats or deceptive tactics detected.",
                "Safe to proceed under standard cyber awareness. Remember that HTTPS alone does not guarantee safety.",
            )
        elif score < 50:
            return (
                RiskLevel.MODERATE,
                "#FFB703",  # Amber Warning
                "warning",
                f"{indicator_count} suspicious indicator(s) identified. Some abnormal or evasive features detected.",
                "Proceed with caution. Carefully verify the destination domain identity before submitting any credentials or personal data.",
            )
        elif score < 75:
            return (
                RiskLevel.HIGH,
                "#FB8500",  # High Alert Orange
                "danger",
                f"Elevated risk! {indicator_count} suspicious indicators detected. High likelihood of deceptive redirection or phishing.",
                "Do NOT enter passwords, account numbers, or personal credentials. Verify this request through a known, trusted official communication channel.",
            )
        else:
            return (
                RiskLevel.CRITICAL,
                "#FF3366",  # Critical Threat Crimson Red
                "danger",
                f"CRITICAL THREAT! Severe deceptive tactics detected ({indicator_count} indicators). Strong indicators of quishing or malicious payload delivery.",
                "ABORT NAVIGATION. Do NOT open this URL or execute downloaded content. This destination matches known attack patterns.",
            )
