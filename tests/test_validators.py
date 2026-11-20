"""Automated tests for scanner/validators.py: image validation, SSRF prevention, and sanitization."""

import io
import pytest
from PIL import Image
from scanner.validators import validate_image_file, is_safe_url_for_lookup, sanitize_text


def _create_test_image(fmt: str = "PNG", size: tuple = (100, 100)) -> bytes:
    """Helper to generate in-memory valid image bytes."""
    buf = io.BytesIO()
    img = Image.new("RGB", size, color="white")
    img.save(buf, format=fmt)
    return buf.getvalue()


class TestImageValidators:
    """Tests for image file validation."""

    def test_valid_png(self):
        png_bytes = _create_test_image("PNG")
        valid, msg, meta = validate_image_file(png_bytes, "test.png")
        assert valid is True
        assert msg == ""
        assert meta["format"] == "PNG"
        assert meta["width"] == 100
        assert meta["height"] == 100

    def test_valid_jpeg(self):
        jpeg_bytes = _create_test_image("JPEG")
        valid, msg, meta = validate_image_file(jpeg_bytes, "test.jpg")
        assert valid is True
        assert meta["format"] == "JPEG"

    def test_valid_webp(self):
        webp_bytes = _create_test_image("WEBP")
        valid, msg, meta = validate_image_file(webp_bytes, "test.webp")
        assert valid is True
        assert meta["format"] == "WEBP"

    def test_empty_bytes(self):
        valid, msg, meta = validate_image_file(b"", "empty.png")
        assert valid is False
        assert "empty" in msg.lower()

    def test_corrupted_image(self):
        corrupt = b"\x89PNG\r\n\x1a\n" + b"CorruptGarbageData1234567890"
        valid, msg, meta = validate_image_file(corrupt, "corrupt.png")
        assert valid is False
        assert "corrupted" in msg.lower() or "invalid" in msg.lower()

    def test_unsupported_extension(self):
        png_bytes = _create_test_image("PNG")
        valid, msg, meta = validate_image_file(png_bytes, "test.pdf")
        assert valid is False
        assert "unsupported file extension" in msg.lower()

    def test_fake_extension_magic_mismatch(self):
        # Text file renamed to .png
        fake_png = b"This is not a real image but renamed to .png"
        valid, msg, meta = validate_image_file(fake_png, "fake.png")
        assert valid is False
        assert "magic bytes" in msg.lower()

    def test_oversized_image(self):
        # 1MB limit for this test
        png_bytes = _create_test_image("PNG")
        valid, msg, meta = validate_image_file(png_bytes, "big.png", max_size_mb=0.0001)
        assert valid is False
        assert "exceeds maximum allowed limit" in msg.lower()


class TestSSRFAndLookupValidators:
    """Tests for is_safe_url_for_lookup (SSRF prevention)."""

    def test_safe_public_https_url(self):
        safe, reason = is_safe_url_for_lookup("https://www.google.com/search?q=cybersecurity")
        assert safe is True
        assert "safe" in reason.lower()

    def test_safe_public_http_url(self):
        safe, reason = is_safe_url_for_lookup("http://example.org/path")
        assert safe is True

    def test_reject_localhost(self):
        safe, reason = is_safe_url_for_lookup("http://localhost:8080/admin")
        assert safe is False
        assert "localhost" in reason.lower()

    def test_reject_loopback_ip(self):
        safe, reason = is_safe_url_for_lookup("http://127.0.0.1:5000/api")
        assert safe is False
        assert "loopback" in reason.lower()

    def test_reject_private_rfc1918_192_168(self):
        safe, reason = is_safe_url_for_lookup("http://192.168.1.1/router-login")
        assert safe is False
        assert "private" in reason.lower()

    def test_reject_private_rfc1918_10(self):
        safe, reason = is_safe_url_for_lookup("http://10.0.0.5:8080/internal")
        assert safe is False
        assert "private" in reason.lower()

    def test_reject_private_rfc1918_172(self):
        safe, reason = is_safe_url_for_lookup("http://172.16.0.100/status")
        assert safe is False
        assert "private" in reason.lower()

    def test_reject_non_http_schemes(self):
        for bad_url in ["file:///etc/passwd", "gopher://evil.com", "javascript:alert(1)", "data:text/html;test"]:
            safe, reason = is_safe_url_for_lookup(bad_url)
            assert safe is False
            assert "unsupported protocol" in reason.lower()

    def test_reject_empty_input(self):
        safe, reason = is_safe_url_for_lookup("")
        assert safe is False


class TestSanitizeText:
    """Tests for HTML escaping and control character sanitization."""

    def test_escape_html(self):
        raw = '<script>alert("XSS")</script>&param=1'
        cleaned = sanitize_text(raw)
        assert "<script>" not in cleaned
        assert "&lt;script&gt;" in cleaned
        assert "&amp;param=1" in cleaned

    def test_strip_null_bytes(self):
        raw = "payload\x00with\x00null\x08bytes"
        cleaned = sanitize_text(raw)
        assert "\x00" not in cleaned
        assert "\x08" not in cleaned
        assert "payloadwithnullbytes" in cleaned

    def test_empty_string(self):
        assert sanitize_text("") == ""
        assert sanitize_text(None) == ""
