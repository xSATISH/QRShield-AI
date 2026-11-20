"""Automated tests for scanner/url_analyzer.py: 14 security rules and URL anatomy extraction."""

import pytest
from scanner.url_analyzer import URLAnalyzer, URLAnalysisResult


class TestURLAnalyzer:
    """Comprehensive test suite for the rule-based URL analysis engine."""

    @pytest.fixture
    def analyzer(self):
        return URLAnalyzer()

    def test_benign_https_url(self, analyzer):
        url = "https://www.example.com/about/team"
        res = analyzer.analyze(url)
        assert res.is_valid is True
        assert res.anatomy.is_https is True
        assert res.anatomy.hostname == "www.example.com"
        assert res.anatomy.registered_domain == "example.com"
        # Should have 0 or minimal indicators
        assert len(res.indicators) == 0

    def test_http_insecure_detected(self, analyzer):
        url = "http://www.example.org/test"
        res = analyzer.analyze(url)
        assert res.is_valid is True
        assert any(ind.id == "HTTP_INSECURE" for ind in res.indicators)

    def test_ip_address_host_detected(self, analyzer):
        url = "http://192.168.1.100/router/settings"
        res = analyzer.analyze(url)
        assert res.is_valid is True
        assert any(ind.id == "IP_ADDRESS_HOST" for ind in res.indicators)

    def test_at_symbol_trick_detected(self, analyzer):
        url = "https://www.paypal.com@evil-phishing-host.com/login"
        res = analyzer.analyze(url)
        assert res.is_valid is True
        assert any(ind.id == "AT_SYMBOL_TRICK" for ind in res.indicators)

    def test_punycode_domain_detected(self, analyzer):
        url = "https://xn--pple-43d.com/support"
        res = analyzer.analyze(url)
        assert res.is_valid is True
        assert any(ind.id == "PUNYCODE_DOMAIN" for ind in res.indicators)

    def test_url_shortener_detected(self, analyzer):
        for shortener in ["https://bit.ly/3xYqz8", "https://tinyurl.com/bank-login", "http://t.co/abc123"]:
            res = analyzer.analyze(shortener)
            assert any(ind.id == "URL_SHORTENER" for ind in res.indicators), f"Failed for {shortener}"

    def test_excessive_subdomains_detected(self, analyzer):
        url = "https://verify.account.security.login.attacker-site.com/portal"
        res = analyzer.analyze(url)
        assert any(ind.id == "EXCESSIVE_SUBDOMAINS" for ind in res.indicators)

    def test_suspicious_keywords_detected(self, analyzer):
        url = "https://account-portal-security.com/login?action=verify&update=password"
        res = analyzer.analyze(url)
        assert any(ind.id == "SUSPICIOUS_KEYWORDS" for ind in res.indicators)

    def test_unusual_port_detected(self, analyzer):
        url = "https://www.example.com:8443/login"
        res = analyzer.analyze(url)
        assert any(ind.id == "UNUSUAL_PORT" for ind in res.indicators)

    def test_suspicious_file_extension_exe(self, analyzer):
        url = "https://security-updates-cdn.net/files/patch_v1.exe"
        res = analyzer.analyze(url)
        assert any(ind.id == "SUSPICIOUS_EXTENSION" for ind in res.indicators)

    def test_suspicious_file_extension_apk(self, analyzer):
        url = "https://banking-app-download.org/app_v4.apk"
        res = analyzer.analyze(url)
        assert any(ind.id == "SUSPICIOUS_EXTENSION" for ind in res.indicators)

    def test_homograph_typosquatting_detected(self, analyzer):
        for fake_domain in ["https://www.paypa1.com/verify", "http://goog1e.com/search", "https://micros0ft.com/update"]:
            res = analyzer.analyze(fake_domain)
            assert any(ind.id == "HOMOGRAPH_TYPOSQUATTING" for ind in res.indicators), f"Failed for {fake_domain}"

    def test_embedded_redirect_detected(self, analyzer):
        url = "https://legit-site.com/redirect?url=https://evil-destination.com/steal"
        res = analyzer.analyze(url)
        assert any(ind.id == "EMBEDDED_REDIRECT" for ind in res.indicators)

    def test_misleading_brand_subdomain_detected(self, analyzer):
        url = "https://paypal.com.payment-gateway-gateway.com/auth"
        res = analyzer.analyze(url)
        assert any(ind.id == "MISLEADING_HOSTNAME" for ind in res.indicators)

    def test_hyphen_stuffed_domain_detected(self, analyzer):
        url = "https://secure-login-online-banking-account.com/home"
        res = analyzer.analyze(url)
        assert any(ind.id == "MISLEADING_HOSTNAME" for ind in res.indicators)

    def test_obfuscated_patterns_double_encoding(self, analyzer):
        url = "https://example.com/%252e%252e/admin"
        res = analyzer.analyze(url)
        assert any(ind.id == "OBFUSCATED_PATTERNS" for ind in res.indicators)

    def test_empty_and_invalid_inputs(self, analyzer):
        res1 = analyzer.analyze("")
        assert res1.is_valid is False
        assert "empty" in res1.error_message.lower()

        res2 = analyzer.analyze("   ")
        assert res2.is_valid is False

        res3 = analyzer.analyze("http://")
        assert res3.is_valid is False
