"""QR Code decoding engine using OpenCV with multi-code detection and robust preprocessing."""

import io
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple, Dict, Any
from urllib.parse import urlparse

import cv2
import numpy as np
from PIL import Image


class ContentType(str, Enum):
    """Enumeration of recognized QR code payload types."""
    URL = "URL"
    PLAIN_TEXT = "Plain Text"
    EMAIL = "Email"
    PHONE = "Phone Number"
    SMS = "SMS Message"
    WIFI = "Wi-Fi Configuration"
    VCARD = "vCard / Contact"
    GEO = "Geographic Location"
    OTHER = "Other / Binary"


@dataclass
class QRScanResult:
    """Represents the decoded result of a single QR code."""
    raw_content: str
    content_type: ContentType
    is_url: bool
    bounding_box: Optional[List[List[float]]] = None
    details: Dict[str, Any] = field(default_factory=dict)
    error_message: str = ""


class QRDecoder:
    """Decodes QR codes from image bytes or NumPy arrays with adaptive preprocessing."""

    def __init__(self):
        self.detector = cv2.QRCodeDetector()

    def decode_image_bytes(self, file_bytes: bytes) -> Tuple[List[QRScanResult], str]:
        """Decode all QR codes present in the raw image bytes.
        
        Returns:
            (results_list, error_message)
        """
        if not file_bytes:
            return [], "Empty image payload provided."

        try:
            # Load with PIL first to safely handle diverse formats (PNG, JPG, WEBP)
            pil_img = Image.open(io.BytesIO(file_bytes)).convert("RGB")
            np_img = np.array(pil_img)
            # OpenCV uses BGR internally
            cv_img = cv2.cvtColor(np_img, cv2.COLOR_RGB2BGR)
        except Exception as e:
            return [], f"Failed to load image for decoding: {str(e)}"

        return self.decode_opencv_image(cv_img)

    def decode_opencv_image(self, img: np.ndarray) -> Tuple[List[QRScanResult], str]:
        """Execute detection pipeline on a cv2 image with fallback preprocessing."""
        if img is None or img.size == 0:
            return [], "Invalid or empty image array."

        # Pass 1: Direct multi-detection on original image
        results = self._try_detect_multi(img)
        if results:
            return results, ""

        # Pass 2: Grayscale conversion
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY) if len(img.shape) == 3 else img
        results = self._try_detect_multi(gray)
        if results:
            return results, ""

        # Pass 3: Contrast Limited Adaptive Histogram Equalization (CLAHE)
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        enhanced = clahe.apply(gray)
        results = self._try_detect_multi(enhanced)
        if results:
            return results, ""

        # Pass 4: Otsu binarization
        _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        results = self._try_detect_multi(otsu)
        if results:
            return results, ""

        # Pass 5: Resize upsampling (for small QR codes)
        h, w = gray.shape[:2]
        if max(h, w) < 600:
            resized = cv2.resize(gray, (w * 2, h * 2), interpolation=cv2.INTER_CUBIC)
            results = self._try_detect_multi(resized)
            if results:
                return results, ""

        return [], "No valid QR code detected in the uploaded image. Please ensure the QR code is clearly visible, focused, and well-lit."

    def _try_detect_multi(self, image: np.ndarray) -> List[QRScanResult]:
        """Attempt detectAndDecodeMulti, falling back to detectAndDecode."""
        try:
            ok, decoded_info, points, _ = self.detector.detectAndDecodeMulti(image)
            results: List[QRScanResult] = []
            if ok and decoded_info is not None:
                for idx, text in enumerate(decoded_info):
                    if text and text.strip():
                        bbox = points[idx].tolist() if points is not None and idx < len(points) else None
                        results.append(self._parse_payload(text.strip(), bbox))
                if results:
                    return results
        except Exception:
            pass

        # Fallback to single detector
        try:
            text, points, _ = self.detector.detectAndDecode(image)
            if text and text.strip():
                bbox = points.tolist() if points is not None else None
                return [self._parse_payload(text.strip(), bbox)]
        except Exception:
            pass

        return []

    def _parse_payload(self, raw_text: str, bbox: Optional[List[List[float]]] = None) -> QRScanResult:
        """Classify the content type of the decoded payload and extract structured details."""
        raw_clean = raw_text.strip()
        content_type, is_url, details = self._classify_content(raw_clean)

        return QRScanResult(
            raw_content=raw_clean,
            content_type=content_type,
            is_url=is_url,
            bounding_box=bbox,
            details=details,
        )

    def _classify_content(self, text: str) -> Tuple[ContentType, bool, Dict[str, Any]]:
        """Determine whether payload is a URL, Wi-Fi, vCard, email, phone, SMS, geo, or plain text."""
        # 1. Wi-Fi Configuration: WIFI:T:WPA;S:MySSID;P:mypass;;
        if text.startswith("WIFI:") or text.startswith("wifi:"):
            details = self._parse_wifi(text)
            return ContentType.WIFI, False, details

        # 2. vCard / MeCard Contact
        if text.startswith("BEGIN:VCARD") or text.startswith("MECARD:"):
            details = self._parse_vcard(text)
            return ContentType.VCARD, False, details

        # 3. Email (mailto: or MATMSG:)
        if text.lower().startswith("mailto:") or text.startswith("MATMSG:"):
            details = self._parse_email(text)
            return ContentType.EMAIL, False, details

        # 4. Telephone (tel:)
        if text.lower().startswith("tel:"):
            number = text[4:].strip()
            return ContentType.PHONE, False, {"phone_number": number}

        # 5. SMS (smsto: or sms:)
        if text.lower().startswith("smsto:") or text.lower().startswith("sms:"):
            details = self._parse_sms(text)
            return ContentType.SMS, False, details

        # 6. Geo location (geo:lat,lon)
        if text.lower().startswith("geo:"):
            details = self._parse_geo(text)
            return ContentType.GEO, False, details

        # 7. URL (Explicit HTTP/HTTPS/FTP or common web schema)
        if re.match(r"^(https?|ftp)://", text, re.IGNORECASE):
            return ContentType.URL, True, {"raw_url": text}

        # Domain-like patterns (e.g. www.example.com or sub.example.org/path)
        common_tlds = (
            r"\.(com|org|net|edu|gov|io|ai|co|xyz|info|top|me|app|dev|cc|ru|cn|in|de|uk|jp|br|pl|tv|online|site|store|tech)"
        )
        if re.match(rf"^(www\.|[a-zA-Z0-9-]{{2,63}}{common_tlds})(\/.*)?$", text, re.IGNORECASE):
            # Normalize with https:// for uniform processing
            normalized_url = "https://" + text
            return ContentType.URL, True, {"raw_url": normalized_url, "scheme_missing": True}

        # 8. Standalone email address without mailto:
        if re.match(r"^[\w\.-]+@[\w\.-]+\.\w{2,}$", text):
            return ContentType.EMAIL, False, {"to": text}

        # 9. Standalone phone number
        if re.match(r"^(\+\d{1,3}[\s-]?)?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}$", text):
            return ContentType.PHONE, False, {"phone_number": text}

        # 10. Default: Plain text
        return ContentType.PLAIN_TEXT, False, {"char_count": len(text)}

    def _parse_wifi(self, text: str) -> Dict[str, Any]:
        """Extract Wi-Fi credentials from standard WIFI: URI format."""
        ssid = re.search(r"S:([^;]+)", text, re.IGNORECASE)
        auth = re.search(r"T:([^;]+)", text, re.IGNORECASE)
        pwd = re.search(r"P:([^;]+)", text, re.IGNORECASE)
        hidden = re.search(r"H:([^;]+)", text, re.IGNORECASE)

        raw_pwd = pwd.group(1) if pwd else ""
        masked_pwd = "*" * len(raw_pwd) if raw_pwd else "(None / Open)"

        return {
            "ssid": ssid.group(1) if ssid else "Unknown",
            "security_type": (auth.group(1) if auth else "WPA").upper(),
            "password_masked": masked_pwd,
            "has_password": bool(raw_pwd),
            "hidden_network": hidden.group(1).lower() == "true" if hidden else False,
        }

    def _parse_vcard(self, text: str) -> Dict[str, Any]:
        """Extract contact fields from vCard or MeCard."""
        fn = re.search(r"\nFN:([^\r\n]+)", text) or re.search(r"N:([^;]+)", text)
        org = re.search(r"\nORG:([^\r\n]+)", text)
        tel = re.search(r"\nTEL[^:]*:([^\r\n]+)", text)
        email = re.search(r"\nEMAIL[^:]*:([^\r\n]+)", text)
        title = re.search(r"\nTITLE:([^\r\n]+)", text)

        return {
            "name": fn.group(1).strip() if fn else "Contact",
            "organization": org.group(1).strip() if org else "",
            "phone": tel.group(1).strip() if tel else "",
            "email": email.group(1).strip() if email else "",
            "title": title.group(1).strip() if title else "",
        }

    def _parse_email(self, text: str) -> Dict[str, Any]:
        """Extract recipient and subject from email URI."""
        if text.lower().startswith("mailto:"):
            url_part = text[7:]
            parsed = urlparse("http://" + url_part) if "//" in url_part else urlparse("mailto:" + url_part)
            recipient = parsed.path
            return {"to": recipient, "uri": text}
        elif text.startswith("MATMSG:"):
            to_m = re.search(r"TO:([^;]+)", text)
            sub_m = re.search(r"SUB:([^;]+)", text)
            body_m = re.search(r"BODY:([^;]+)", text)
            return {
                "to": to_m.group(1) if to_m else "",
                "subject": sub_m.group(1) if sub_m else "",
                "body": body_m.group(1) if body_m else "",
            }
        return {"to": text}

    def _parse_sms(self, text: str) -> Dict[str, Any]:
        """Extract phone and message from SMS URI."""
        # e.g. smsto:+123456:Hello world
        parts = text.split(":", 2)
        number = parts[1] if len(parts) > 1 else ""
        body = parts[2] if len(parts) > 2 else ""
        return {"recipient": number, "message": body}

    def _parse_geo(self, text: str) -> Dict[str, Any]:
        """Extract latitude, longitude from geo URI."""
        coords = text[4:].split("?")[0].split(",")
        lat = coords[0].strip() if len(coords) > 0 else "0"
        lon = coords[1].strip() if len(coords) > 1 else "0"
        return {"latitude": lat, "longitude": lon}
