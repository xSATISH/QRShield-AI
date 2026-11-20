"""Input validation, security sanitization, and SSRF prevention utilities for QRShield AI."""

import html
import io
import ipaddress
import os
import re
from typing import Dict, Tuple, Any
from urllib.parse import urlparse
from PIL import Image

# Maximum allowed upload size (10 MB to prevent memory exhaustion / DoS)
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp"}

# Standard magic bytes for image formats
MAGIC_BYTES = {
    "png": b"\x89PNG\r\n\x1a\n",
    "jpeg": b"\xff\xd8\xff",
    "webp_riff": b"RIFF",
    "webp_vp8": b"WEBP",
}


def sanitize_text(text: str) -> str:
    """Sanitize arbitrary text or decoded QR contents.
    
    Neutralizes null bytes, control characters, and escapes HTML
    to avoid Stored/Reflected XSS or formatting manipulation.
    """
    if not isinstance(text, str):
        return ""
    # Strip null bytes and non-printable control chars except \n, \r, \t
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    # HTML escape
    return html.escape(cleaned, quote=True)


def validate_image_file(file_bytes: bytes, filename: str = "", max_size_mb: float = 10.0) -> Tuple[bool, str, Dict[str, Any]]:
    """Validate uploaded image file bytes for size, format, magic headers, and image integrity.
    
    Returns:
        (is_valid, error_message, metadata_dict)
    """
    if not file_bytes:
        return False, "Uploaded file is empty (0 bytes).", {}

    max_bytes = int(max_size_mb * 1024 * 1024)
    if len(file_bytes) > max_bytes:
        size_mb = len(file_bytes) / (1024 * 1024)
        return False, f"File size ({size_mb:.2f} MB) exceeds maximum allowed limit of {max_size_mb:.1f} MB.", {}

    if filename:
        _, ext = os.path.splitext(filename.lower())
        if ext and ext not in ALLOWED_EXTENSIONS:
            allowed_str = ", ".join(sorted(ALLOWED_EXTENSIONS))
            return False, f"Unsupported file extension '{ext}'. Allowed formats: {allowed_str}.", {}

    # Magic bytes verification
    is_png = file_bytes.startswith(MAGIC_BYTES["png"])
    is_jpeg = file_bytes.startswith(MAGIC_BYTES["jpeg"])
    is_webp = file_bytes.startswith(MAGIC_BYTES["webp_riff"]) and len(file_bytes) >= 12 and file_bytes[8:12] == MAGIC_BYTES["webp_vp8"]

    if not (is_png or is_jpeg or is_webp):
        return False, "File header does not match valid PNG, JPEG, or WEBP magic bytes.", {}

    # Pillow integrity check
    try:
        with Image.open(io.BytesIO(file_bytes)) as img:
            img.verify()
            format_name = (img.format or "UNKNOWN").upper()
            
        # Re-open after verify() to read dimensions safely
        with Image.open(io.BytesIO(file_bytes)) as img:
            width, height = img.size
            if width < 10 or height < 10:
                return False, f"Image dimensions too small ({width}x{height}px) to contain a readable QR code.", {}
            if width > 8000 or height > 8000:
                return False, f"Image dimensions too large ({width}x{height}px). Max limit is 8000x8000px.", {}

            metadata = {
                "format": format_name,
                "width": width,
                "height": height,
                "size_kb": round(len(file_bytes) / 1024, 2),
                "filename": filename or "uploaded_image",
            }
            return True, "", metadata
    except Exception as e:
        return False, f"Corrupted or invalid image data: {str(e)}", {}


def is_safe_url_for_lookup(url: str) -> Tuple[bool, str]:
    """Validate that a URL is safe for external threat reputation lookup.
    
    Protects against Server-Side Request Forgery (SSRF) and local network scanning.
    Rejects:
    - Non-HTTP/HTTPS schemes
    - Localhost, 127.0.0.1, ::1
    - RFC 1918 private IPv4 subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    - Link-local (169.254.0.0/16, fe80::/10)
    - Loopback, unspecified, and multicast IPs
    - Missing hostnames or credentials in hostname
    
    Returns:
        (is_safe, reason)
    """
    if not url or not isinstance(url, str):
        return False, "Empty or invalid URL input."

    url_clean = url.strip()
    try:
        parsed = urlparse(url_clean)
    except Exception as e:
        return False, f"Failed to parse URL structure: {str(e)}"

    if parsed.scheme.lower() not in ("http", "https"):
        return False, f"Unsupported protocol '{parsed.scheme}'. Only HTTP and HTTPS lookups are permitted."

    hostname = parsed.hostname
    if not hostname:
        return False, "URL contains no identifiable host or domain name."

    hostname = hostname.strip().lower()

    # Block localhost by name
    if hostname in ("localhost", "localhost.localdomain", "broadcasthost"):
        return False, "Target host is localhost; external threat lookup blocked for security (SSRF prevention)."

    # Check for IP address notation
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_loopback:
            return False, f"Target IP {ip} is a loopback address; lookup blocked (SSRF prevention)."
        if ip.is_private:
            return False, f"Target IP {ip} is a private network address; lookup blocked (SSRF prevention)."
        if ip.is_link_local:
            return False, f"Target IP {ip} is a link-local address; lookup blocked (SSRF prevention)."
        if ip.is_multicast or ip.is_unspecified:
            return False, f"Target IP {ip} is reserved/multicast; lookup blocked (SSRF prevention)."
    except ValueError:
        # Not a bare IP, it's a domain name
        pass

    # Basic domain syntax sanity
    if len(hostname) > 253 or " " in hostname:
        return False, "Malformed domain name syntax."

    return True, "URL is safe for threat intelligence querying."
