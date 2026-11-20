"""Automated tests for scanner/decoder.py: QR decoding, multi-code handling, and payload parsing."""

import io
import pytest
import qrcode
from PIL import Image
from scanner.decoder import QRDecoder, ContentType, QRScanResult


def _generate_qr_bytes(text: str) -> bytes:
    """Helper to generate in-memory PNG bytes of a QR code."""
    qr = qrcode.QRCode(box_size=8, border=2)
    qr.add_data(text)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


class TestQRDecoder:
    """Unit tests for the OpenCV-based QR decoder."""

    @pytest.fixture
    def decoder(self):
        return QRDecoder()

    def test_decode_valid_https_url(self, decoder):
        url = "https://www.example.com/secure-path?ref=test"
        qr_bytes = _generate_qr_bytes(url)
        results, err = decoder.decode_image_bytes(qr_bytes)
        assert err == ""
        assert len(results) >= 1
        res = results[0]
        assert res.raw_content == url
        assert res.content_type == ContentType.URL
        assert res.is_url is True

    def test_decode_plain_text(self, decoder):
        text = "Confidential Security Audit Note - Project QRShield"
        qr_bytes = _generate_qr_bytes(text)
        results, err = decoder.decode_image_bytes(qr_bytes)
        assert err == ""
        assert len(results) >= 1
        res = results[0]
        assert res.raw_content == text
        assert res.content_type == ContentType.PLAIN_TEXT
        assert res.is_url is False

    def test_decode_wifi_configuration(self, decoder):
        wifi_str = "WIFI:T:WPA;S:SecureCorp_Guest;P:SuperSecretPass123;;"
        qr_bytes = _generate_qr_bytes(wifi_str)
        results, err = decoder.decode_image_bytes(qr_bytes)
        assert err == ""
        assert len(results) >= 1
        res = results[0]
        assert res.content_type == ContentType.WIFI
        assert res.is_url is False
        assert res.details.get("ssid") == "SecureCorp_Guest"
        assert res.details.get("security_type") == "WPA"
        assert res.details.get("has_password") is True
        assert res.details.get("password_masked") == "******************"

    def test_decode_email_mailto(self, decoder):
        mailto = "mailto:security-team@example.org?subject=Incident"
        qr_bytes = _generate_qr_bytes(mailto)
        results, err = decoder.decode_image_bytes(qr_bytes)
        assert err == ""
        assert len(results) >= 1
        res = results[0]
        assert res.content_type == ContentType.EMAIL
        assert res.is_url is False

    def test_decode_phone(self, decoder):
        phone = "tel:+18005550199"
        qr_bytes = _generate_qr_bytes(phone)
        results, err = decoder.decode_image_bytes(qr_bytes)
        assert err == ""
        assert len(results) >= 1
        res = results[0]
        assert res.content_type == ContentType.PHONE
        assert res.is_url is False
        assert res.details.get("phone_number") == "+18005550199"

    def test_decode_empty_bytes(self, decoder):
        results, err = decoder.decode_image_bytes(b"")
        assert len(results) == 0
        assert "empty" in err.lower()

    def test_decode_image_without_qr_code(self, decoder):
        # Plain white image
        buf = io.BytesIO()
        Image.new("RGB", (200, 200), color="white").save(buf, format="PNG")
        results, err = decoder.decode_image_bytes(buf.getvalue())
        assert len(results) == 0
        assert "no valid qr code detected" in err.lower()

    def test_decode_corrupted_image_bytes(self, decoder):
        corrupt = b"\x89PNG\r\n\x1a\nCorruptPayloadData"
        results, err = decoder.decode_image_bytes(corrupt)
        assert len(results) == 0
        assert "failed to load" in err.lower()
