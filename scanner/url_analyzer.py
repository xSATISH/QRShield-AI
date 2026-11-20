"""Transparent, rule-based URL security analysis engine for QRShield AI."""

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse, parse_qs, unquote


# Known public URL shortener domains
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "rebrand.ly", "buff.ly",
    "cutt.ly", "tiny.cc", "bc.vc", "goo.gl", "v.gd", "qr.ae", "rb.gy",
    "shorturl.at", "clck.ru", "rotf.lol", "soo.gd", "s.id", "trib.al",
    "ift.tt", "bl.ink", "snip.ly", "dub.sh", "t.ly", "shortcm.li",
}

# Suspicious payload file extensions
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".apk", ".bat", ".cmd", ".vbs", ".ps1", ".msi", ".iso",
    ".zip", ".rar", ".7z", ".hta", ".jar", ".reg", ".dll", ".bin", ".cab",
    ".dmg", ".pkg", ".deb", ".rpm", ".sh", ".wsf", ".vbe", ".jse"
}

# Suspicious phishing and social engineering keywords
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "account", "password", "banking",
    "paypal", "wallet", "signin", "confirm", "security", "recover", "billing",
    "auth", "credential", "validation", "support-desk", "webscr", "authenticate",
    "passcode", "identity", "suspended", "unusual-activity", "kyc-verify"
]

# Major brands commonly impersonated via typosquatting or homoglyphs
POPULAR_BRANDS = [
    "google", "paypal", "microsoft", "apple", "amazon", "facebook", "netflix",
    "instagram", "whatsapp", "twitter", "chase", "wellsfargo", "bankofamerica",
    "binance", "coinbase", "dropbox", "github", "telegram", "yahoo", "linkedin"
]

# Redirect / forward query parameters
REDIRECT_PARAMS = {
    "url", "redirect", "redirect_to", "redirect_url", "next", "dest",
    "destination", "target", "return", "return_url", "goto", "r", "link",
    "u", "out", "forward", "continue", "checkout_url", "open"
}

# Standard public web ports
STANDARD_PORTS = {80, 443}


@dataclass
class SecurityIndicator:
    """Represents a discrete security finding detected during URL analysis."""
    id: str
    title: str
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    category: str
    description: str
    evidence: str
    recommendation: str


@dataclass
class URLAnatomy:
    """Deconstructed structural components of the analyzed URL."""
    raw_url: str
    scheme: str
    hostname: str
    registered_domain: str
    subdomain: str
    port: Optional[int]
    path: str
    query_params: Dict[str, List[str]]
    fragment: str
    is_https: bool


@dataclass
class URLAnalysisResult:
    """Comprehensive output of the URL security inspection."""
    url: str
    is_valid: bool
    anatomy: Optional[URLAnatomy]
    indicators: List[SecurityIndicator] = field(default_factory=list)
    error_message: str = ""


class URLAnalyzer:
    """Rule-based security engine that evaluates URLs across 14 distinct threat vectors."""

    def analyze(self, raw_url: str) -> URLAnalysisResult:
        """Analyze a destination URL for manipulation, spoofing, and evasion techniques."""
        if not raw_url or not isinstance(raw_url, str):
            return URLAnalysisResult(url="", is_valid=False, anatomy=None, error_message="Empty URL provided.")

        url_str = raw_url.strip()
        # Prepend https:// if raw text looks like domain but lacks scheme for uniform parsing
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url_str):
            if re.match(r"^www\.|^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", url_str):
                url_str = "http://" + url_str

        try:
            parsed = urlparse(url_str)
        except Exception as e:
            return URLAnalysisResult(url=raw_url, is_valid=False, anatomy=None, error_message=f"Malformed URL: {str(e)}")

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return URLAnalysisResult(url=raw_url, is_valid=False, anatomy=None, error_message="URL does not contain a valid hostname.")

        subdomain, reg_domain = self._split_domain(hostname)
        query_dict = parse_qs(parsed.query, keep_blank_values=True)

        anatomy = URLAnatomy(
            raw_url=url_str,
            scheme=parsed.scheme.lower(),
            hostname=hostname,
            registered_domain=reg_domain,
            subdomain=subdomain,
            port=parsed.port,
            path=parsed.path,
            query_params=query_dict,
            fragment=parsed.fragment,
            is_https=parsed.scheme.lower() == "https",
        )

        indicators: List[SecurityIndicator] = []

        # 1. HTTP instead of HTTPS
        self._check_http_scheme(anatomy, indicators)

        # 2. IP address used instead of domain name
        self._check_ip_address_host(anatomy, indicators)

        # 3. URL shortening services
        self._check_url_shortener(anatomy, indicators)

        # 4. Excessive subdomains
        self._check_excessive_subdomains(anatomy, indicators)

        # 5. Suspicious URL length
        self._check_suspicious_length(anatomy, indicators)

        # 6. URL containing @ symbols
        self._check_at_symbol_trick(url_str, parsed, indicators)

        # 7. Punycode domains (xn--)
        self._check_punycode(anatomy, indicators)

        # 8. Suspicious keywords in domain, subdomain, or path
        self._check_suspicious_keywords(anatomy, indicators)

        # 9. Unusual port numbers
        self._check_unusual_port(anatomy, indicators)

        # 10. Encoded or obfuscated URL patterns
        self._check_obfuscated_patterns(url_str, anatomy, indicators)

        # 11. Suspicious file extensions
        self._check_suspicious_extension(anatomy, indicators)

        # 12. Homograph / Typosquatting lookalikes
        self._check_homograph_typosquatting(anatomy, indicators)

        # 13. Embedded redirect parameters
        self._check_embedded_redirect(anatomy, indicators)

        # 14. Misleading domain names and unusual hostname structures
        self._check_misleading_hostname(anatomy, indicators)

        return URLAnalysisResult(
            url=url_str,
            is_valid=True,
            anatomy=anatomy,
            indicators=indicators,
        )

    # =========================================================================
    # Rule Evaluation Methods
    # =========================================================================

    def _check_http_scheme(self, anatomy: URLAnatomy, indicators: List[SecurityIndicator]):
        """Rule 1: Detect insecure plain HTTP connection."""
        if anatomy.scheme == "http":
            indicators.append(
                SecurityIndicator(
                    id="HTTP_INSECURE",
                    title="Insecure HTTP Protocol",
                    severity="MEDIUM",
                    category="Transport Security",
                    description="The URL uses unencrypted plain HTTP instead of HTTPS. Traffic, authentication tokens, and user inputs can be intercepted or altered via Man-in-the-Middle (MITM) attacks. Note: While legitimate modern websites use HTTPS, HTTPS alone does not guarantee a site is benign.",
                    evidence=f"Scheme: {anatomy.scheme}://",
                    recommendation="Avoid entering credentials, personal information, or payment details over plain HTTP.",
                )
            )

    def _check_ip_address_host(self, anatomy: URLAnatomy, indicators: List[SecurityIndicator]):
        """Rule 2: Detect raw IP addresses used as the host."""
        host = anatomy.hostname
        is_ip = False
        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            # Check for hex/octal or integer IP notation
            if re.match(r"^0x[0-9a-fA-F]+$|^\d{8,10}$", host):
                is_ip = True

        if is_ip:
            indicators.append(
                SecurityIndicator(
                    id="IP_ADDRESS_HOST",
                    title="Raw IP Address as Hostname",
                    severity="HIGH",
                    category="Host Identification",
                    description="The URL references a raw IP address directly instead of a registered domain name. Phishing campaigns, rogue servers, and botnet command nodes frequently employ bare IP addresses to evade standard domain reputation blocklists.",
                    evidence=f"Host: {host}",
                    recommendation="Exercise high caution. Legitimate business services almost universally operate under registered domain names.",
                )
            )

    def _check_url_shortener(self, anatomy: URLAnatomy, indicators: List[SecurityIndicator]):
        """Rule 3: Detect public URL shortening services."""
        domain_to_check = anatomy.registered_domain.lower()
        if domain_to_check in SHORTENER_DOMAINS or anatomy.hostname.lower() in SHORTENER_DOMAINS:
            indicators.append(
                SecurityIndicator(
                    id="URL_SHORTENER",
                    title="URL Shortening Service Detected",
                    severity="HIGH",
                    category="Destination Obfuscation",
                    description=f"The domain '{domain_to_check}' is a known URL shortener. Shortened links conceal the ultimate destination, path, and security properties of the website from the user prior to navigation.",
                    evidence=f"Shortener Host: {anatomy.hostname}",
                    recommendation="Do not open shortened links blindly. Use a link unshortener or inspection service to reveal the destination URL.",
                )
            )

    def _check_excessive_subdomains(self, anatomy: URLAnatomy, indicators: List[SecurityIndicator]):
        """Rule 4: Detect deep or excessive subdomain nesting."""
        if anatomy.subdomain:
            parts = [p for p in anatomy.subdomain.split(".") if p]
            if len(parts) >= 3:
                indicators.append(
                    SecurityIndicator(
                        id="EXCESSIVE_SUBDOMAINS",
                        title="Excessive Subdomain Nesting",
                        severity="MEDIUM",
                        category="Domain Structure",
                        description=f"The URL contains {len(parts)} subdomain levels ('{anatomy.subdomain}'). Cybercriminals chain multiple subdomains to mimic legitimate brand URLs (e.g. login.bank.com.attacker.com) while keeping the real parent domain hidden.",
                        evidence=f"Subdomains: {anatomy.subdomain} ({len(parts)} levels)",
                        recommendation="Inspect the rightmost registered domain name carefully to confirm the actual entity hosting the site.",
                    )
                )

    def _check_suspicious_length(self, anatomy: URLAnatomy, indicators: List[SecurityIndicator]):
        """Rule 5: Detect unusually lengthy URLs."""
        url_len = len(anatomy.raw_url)
        path_len = len(anatomy.path + "?" + urlparse(anatomy.raw_url).query)

        if url_len > 120 or path_len > 100:
            severity = "HIGH" if url_len > 200 else "LOW"
            indicators.append(
                SecurityIndicator(
                    id="SUSPICIOUS_LENGTH",
                    title="Abnormally Long URL Structure",
                    severity=severity,
                    category="URL Complexity",
                    description=f"The total URL length is {url_len} characters. Unusually long URLs are frequently utilized in phishing to pad the address bar, push the actual domain out of view on mobile screens, or carry obfuscated tracking payloads.",
                    evidence=f"URL Length: {url_len} chars (Threshold: 120 chars)",
                    recommendation="Carefully examine the true destination domain, particularly on mobile devices where URL bars truncate long strings.",
                )
            )

    def _check_at_symbol_trick(self, raw_url: str, parsed: Any, indicators: List[SecurityIndicator]):
        """Rule 6: Detect '@' symbol in URL authority / credentials."""
        # Standard URL parsing: everything before @ in netloc is treated as userinfo (ignored by server)
        # e.g. https://google.com@evil.com actually connects to evil.com
        netloc = parsed.netloc or ""
        if "@" in netloc or ("@" in raw_url.split("?")[0].split("#")[0] and not raw_url.lower().startswith("mailto:")):
            indicators.append(
                SecurityIndicator(
                    id="AT_SYMBOL_TRICK",
                    title="Embedded Userinfo '@' Obfuscation",
                    severity="CRITICAL",
                    category="Host Deception",
                    description="The URL contains an '@' symbol in its network authority. Browsers interpret text preceding the '@' as authentication userinfo and navigate exclusively to the host following the '@'. This classic trick is used to display a trusted brand name before the '@' while routing victims to an attacker's server.",
                    evidence=f"Authority: {netloc}",
                    recommendation="Do not visit this URL. The text before '@' is deceptive and does not represent the destination host.",
                )
            )

    def _check_punycode(self, anatomy: URLAnatomy, indicators: List[SecurityIndicator]):
        """Rule 7: Detect Punycode / IDN homograph representation."""
        if "xn--" in anatomy.hostname.lower():
            try:
                decoded_host = anatomy.hostname.encode("ascii").decode("idna")
            except Exception:
                decoded_host = "Unknown (decode error)"

            indicators.append(
                SecurityIndicator(
                    id="PUNYCODE_DOMAIN",
                    title="Punycode / IDN Homograph Domain Detected",
                    severity="HIGH",
                    category="Domain Spoofing",
                    description="The domain uses Punycode encoding ('xn--'), representing Internationalized Domain Names. While legitimate for non-Latin languages, attackers frequently weaponize Punycode in IDN homograph attacks to substitute Latin letters with identical-looking Cyrillic or Greek glyphs.",
                    evidence=f"Encoded: {anatomy.hostname} | Decoded: {decoded_host}",
                    recommendation="Verify the decoded domain spelling character-by-character to ensure characters have not been swapped with visual lookalikes.",
                )
            )

    def _check_suspicious_keywords(self, anatomy: URLAnatomy, indicators: List[SecurityIndicator]):
        """Rule 8: Detect high-risk security and credential keywords in URL parts."""
        combined_target = f"{anatomy.subdomain} {anatomy.path} {' '.join(anatomy.query_params.keys())}".lower()
        matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in combined_target]

        if matched_keywords:
            # If the domain is an official brand (e.g. chase.com) and the only match is its own business term (e.g. 'banking'),
            # and no deceptive indicators exist, avoid a false alarm.
            reg_domain = anatomy.registered_domain.lower()
            if any(brand in reg_domain for brand in POPULAR_BRANDS) and matched_keywords == ["banking"]:
                return

            severity = "HIGH" if len(matched_keywords) >= 2 else "MEDIUM"
            indicators.append(
                SecurityIndicator(
                    id="SUSPICIOUS_KEYWORDS",
                    title="Credential / Authentication Keywords Detected",
                    severity=severity,
                    category="Social Engineering",
                    description=f"The URL contains security-sensitive keywords ({', '.join(matched_keywords[:4])}). These terms are prevalent in quishing campaigns designed to coerce victims into resetting passwords, verifying identities, or logging into fake portals.",
                    evidence=f"Found: {', '.join(matched_keywords)}",
                    recommendation="If this page requests your password, PIN, 2FA code, or personal details, verify the website through an independent official channel first.",
                )
            )

    def _check_unusual_port(self, anatomy: URLAnatomy, indicators: List[SecurityIndicator]):
        """Rule 9: Detect non-standard network ports."""
        if anatomy.port is not None and anatomy.port not in STANDARD_PORTS:
            indicators.append(
                SecurityIndicator(
                    id="UNUSUAL_PORT",
                    title=f"Non-Standard Port Specified (:{anatomy.port})",
                    severity="HIGH",
                    category="Network Configuration",
                    description=f"The URL specifies custom port {anatomy.port}. Standard web traffic uses port 80 (HTTP) or 443 (HTTPS). Attackers and command servers often run phishing or malware staging handlers on unconventional ports to bypass basic corporate proxy filters.",
                    evidence=f"Port: {anatomy.port}",
                    recommendation="Exercise caution when visiting web services hosted on unusual non-standard ports.",
                )
            )

    def _check_obfuscated_patterns(self, raw_url: str, anatomy: URLAnatomy, indicators: List[SecurityIndicator]):
        """Rule 10: Detect obfuscated encoding, double encoding, or directory traversal."""
        findings = []

        # Double URL encoding: %25 followed by hex digits (e.g. %252f, %252e)
        if re.search(r"%25[0-9a-fA-F]{2}", raw_url):
            findings.append("Double URL encoding (%25XX)")

        # Directory traversal tokens encoded (%2e%2e, %2f, %5c)
        if re.search(r"%(?:2e|2f|5c)", raw_url, re.IGNORECASE):
            findings.append("Encoded path traversal tokens (%2e / %2f / %5c)")

        # Hex or octal IP notation in hostname
        if re.search(r"0x[0-9a-fA-F]+", anatomy.hostname) or re.search(r"\b0\d{2,3}\b", anatomy.hostname):
            findings.append("Hexadecimal or Octal IP notation")

        # Excessive percent characters in path/query (> 5)
        percent_count = raw_url.count("%")
        if percent_count > 6:
            findings.append(f"Excessive percent encoding ({percent_count} encoded tokens)")

        if findings:
            indicators.append(
                SecurityIndicator(
                    id="OBFUSCATED_PATTERNS",
                    title="URL Obfuscation Techniques Detected",
                    severity="HIGH",
                    category="Evasion Techniques",
                    description=f"The URL employs obfuscation patterns ({'; '.join(findings)}). These techniques are engineered to evade web application firewalls (WAF), automated URL scanners, and heuristic security filters.",
                    evidence=", ".join(findings),
                    recommendation="Avoid loading URLs that utilize evasion or multiple encoding layers.",
                )
            )

    def _check_suspicious_extension(self, anatomy: URLAnatomy, indicators: List[SecurityIndicator]):
        """Rule 11: Detect dangerous executable, installer, or script extensions."""
        path_lower = anatomy.path.lower()
        matched_ext = None
        for ext in SUSPICIOUS_EXTENSIONS:
            if path_lower.endswith(ext) or f"{ext}?" in path_lower or f"{ext}&" in path_lower:
                matched_ext = ext
                break

        # Also inspect query parameter values for file extensions
        if not matched_ext:
            for vals in anatomy.query_params.values():
                for v in vals:
                    v_low = v.lower()
                    for ext in SUSPICIOUS_EXTENSIONS:
                        if v_low.endswith(ext):
                            matched_ext = ext
                            break
                    if matched_ext:
                        break

        if matched_ext:
            indicators.append(
                SecurityIndicator(
                    id="SUSPICIOUS_EXTENSION",
                    title=f"Dangerous File Extension Detected ({matched_ext})",
                    severity="CRITICAL",
                    category="Malware Delivery",
                    description=f"The URL points directly to an executable, installer, archive, or script file with extension '{matched_ext}'. Opening this destination may initiate an automatic download or execution of malicious binaries.",
                    evidence=f"File extension: {matched_ext} in {anatomy.path}",
                    recommendation="Do not open or download files from this link. Scanning a QR code should not trigger binary downloads.",
                )
            )

    def _check_homograph_typosquatting(self, anatomy: URLAnatomy, indicators: List[SecurityIndicator]):
        """Rule 12: Detect lookalike brand typosquatting patterns."""
        reg_domain = anatomy.registered_domain.lower()
        domain_name = reg_domain.split(".")[0] if "." in reg_domain else reg_domain

        # Common character substitutions: '1' -> 'l' or 'i', '0' -> 'o', 'rn' -> 'm', 'vv' -> 'w'
        normalized = (
            domain_name.replace("1", "l")
            .replace("0", "o")
            .replace("vv", "w")
            .replace("rn", "m")
            .replace("-", "")
        )

        for brand in POPULAR_BRANDS:
            # Check if domain is a substitution clone but NOT the actual brand domain
            if brand in normalized and brand not in domain_name:
                indicators.append(
                    SecurityIndicator(
                        id="HOMOGRAPH_TYPOSQUATTING",
                        title=f"Potential Brand Typosquatting ({brand.capitalize()})",
                        severity="HIGH",
                        category="Brand Impersonation",
                        description=f"The domain '{anatomy.registered_domain}' incorporates visual character substitutions mimicking the legitimate brand '{brand.capitalize()}'. Typosquatters replace letters (such as '0' for 'o' or '1' for 'l') to trick users into confusing fake portals for genuine services.",
                        evidence=f"Suspect domain '{domain_name}' mimics '{brand}'",
                        recommendation=f"Do not trust this domain. Access '{brand.capitalize()}' solely through its verified, bookmark-stored official address.",
                    )
                )
                break

    def _check_embedded_redirect(self, anatomy: URLAnatomy, indicators: List[SecurityIndicator]):
        """Rule 13: Detect open redirect parameters."""
        redirect_findings = []
        for param, vals in anatomy.query_params.items():
            if param.lower() in REDIRECT_PARAMS:
                for v in vals:
                    if re.match(r"^(https?:/|//)", v) or "." in v:
                        redirect_findings.append(f"{param}={v[:50]}")

        if redirect_findings:
            indicators.append(
                SecurityIndicator(
                    id="EMBEDDED_REDIRECT",
                    title="Embedded Open Redirect Parameter",
                    severity="MEDIUM",
                    category="Redirection Risk",
                    description=f"The URL contains open redirect parameters ({', '.join(redirect_findings[:2])}). Cybercriminals exploit legitimate websites with open redirect vulnerabilities to route victims from a trusted domain directly to a malicious landing page.",
                    evidence="; ".join(redirect_findings),
                    recommendation="Verify whether the target parameter routes to a trusted domain before continuing.",
                )
            )

    def _check_misleading_hostname(self, anatomy: URLAnatomy, indicators: List[SecurityIndicator]):
        """Rule 14: Detect deceptive compound domain structures and hyphen-stuffing."""
        host = anatomy.hostname.lower()
        reg_domain = anatomy.registered_domain.lower()
        subdomain = anatomy.subdomain.lower()

        # Check for brand names in subdomain when registered domain is completely different
        brand_in_subdomain = None
        for brand in POPULAR_BRANDS:
            if brand in subdomain and brand not in reg_domain:
                brand_in_subdomain = brand
                break

        if brand_in_subdomain:
            indicators.append(
                SecurityIndicator(
                    id="MISLEADING_HOSTNAME",
                    title=f"Deceptive Brand Subdomain Spoofing ({brand_in_subdomain.capitalize()})",
                    severity="HIGH",
                    category="Domain Spoofing",
                    description=f"The subdomain includes the brand name '{brand_in_subdomain.capitalize()}', but the actual registered domain controlling the website is '{anatomy.registered_domain}'. Attackers use this structure to deceive users who only glance at the start of the URL.",
                    evidence=f"Subdomain: '{subdomain}' | Actual Domain: '{reg_domain}'",
                    recommendation=f"This site is NOT operated by {brand_in_subdomain.capitalize()}. It is hosted by '{reg_domain}'.",
                )
            )

        # Hyphen-stuffed domains (e.g. secure-login-bank-verification-account.com)
        domain_parts = reg_domain.split(".")[0] if "." in reg_domain else reg_domain
        hyphen_count = domain_parts.count("-")
        if hyphen_count >= 3:
            indicators.append(
                SecurityIndicator(
                    id="MISLEADING_HOSTNAME",
                    title="Excessive Hyphen-Stuffed Domain",
                    severity="MEDIUM",
                    category="Domain Structure",
                    description=f"The domain name contains {hyphen_count} hyphens ('{anatomy.registered_domain}'). Hyphen-stuffed domains are characteristic of disposable phishing registrations attempting to construct convincing legitimate-sounding phrases.",
                    evidence=f"Hyphens in domain: {hyphen_count}",
                    recommendation="Exercise caution with domains constructed from multiple hyphenated keywords.",
                )
            )

    # =========================================================================
    # Helpers
    # =========================================================================

    def _split_domain(self, hostname: str) -> Tuple[str, str]:
        """Split hostname into (subdomain, registered_domain)."""
        parts = hostname.split(".")
        if len(parts) <= 2:
            return "", hostname

        # Handle multi-part TLDs like .co.uk, .gov.in, .edu.au, .com.br, etc.
        two_part_tlds = {"co.uk", "gov.uk", "ac.uk", "com.au", "gov.in", "co.in", "net.in", "org.in", "com.br", "co.jp"}
        if len(parts) >= 3:
            potential_tld = f"{parts[-2]}.{parts[-1]}"
            if potential_tld in two_part_tlds:
                if len(parts) == 3:
                    return "", hostname
                registered_domain = f"{parts[-3]}.{potential_tld}"
                subdomain = ".".join(parts[:-3])
                return subdomain, registered_domain

        registered_domain = f"{parts[-2]}.{parts[-1]}"
        subdomain = ".".join(parts[:-2])
        return subdomain, registered_domain
