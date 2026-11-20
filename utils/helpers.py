"""UI helpers, Plotly cybersecurity visual analytics, and QR demo generator."""

import io
from typing import Dict, List, Any
import pandas as pd
import plotly.graph_objects as go
import qrcode
from PIL import Image


def get_custom_css() -> str:
    """Return custom CSS for premium dark cybersecurity dashboard styling."""
    return """
    <style>
    /* Dark Cybersecurity Palette */
    :root {
        --bg-main: #0B0F19;
        --card-bg: #111827;
        --card-border: rgba(0, 229, 255, 0.2);
        --accent-cyan: #00F5D4;
        --accent-blue: #00E5FF;
        --alert-crimson: #FF3366;
        --alert-amber: #FFB703;
        --alert-green: #06D6A0;
    }

    /* Overall App Viewport & Typography */
    .stApp {
        background-color: #0B0F19;
        color: #E2E8F0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }

    /* Headers styling */
    h1, h2, h3, h4 {
        color: #FFFFFF !important;
        font-weight: 700 !important;
        letter-spacing: -0.02em;
    }

    /* Main brand title glow */
    .cyber-title {
        font-size: 2.2rem;
        font-weight: 800;
        background: linear-gradient(135deg, #00E5FF 0%, #00F5D4 50%, #3B82F6 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem;
        text-shadow: 0 0 30px rgba(0, 229, 255, 0.3);
    }

    .cyber-subtitle {
        color: #94A3B8;
        font-size: 0.95rem;
        margin-bottom: 1.5rem;
    }

    /* Glassmorphism Card Container */
    .cyber-card {
        background-color: #111827;
        border: 1px solid rgba(0, 229, 255, 0.2);
        border-radius: 12px;
        padding: 1.25rem 1.5rem;
        margin-bottom: 1.25rem;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }

    .cyber-card:hover {
        border-color: rgba(0, 229, 255, 0.45);
    }

    /* Pill Badges */
    .badge-critical {
        background: rgba(255, 51, 102, 0.15);
        color: #FF3366;
        border: 1px solid #FF3366;
        padding: 4px 12px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 0.85rem;
        display: inline-block;
    }

    .badge-high {
        background: rgba(251, 133, 0, 0.15);
        color: #FB8500;
        border: 1px solid #FB8500;
        padding: 4px 12px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 0.85rem;
        display: inline-block;
    }

    .badge-moderate {
        background: rgba(255, 183, 3, 0.15);
        color: #FFB703;
        border: 1px solid #FFB703;
        padding: 4px 12px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 0.85rem;
        display: inline-block;
    }

    .badge-low {
        background: rgba(6, 214, 160, 0.15);
        color: #06D6A0;
        border: 1px solid #06D6A0;
        padding: 4px 12px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 0.85rem;
        display: inline-block;
    }

    /* Monospace Decoded Payload Box */
    .payload-display {
        font-family: 'Consolas', 'Fira Code', 'Courier New', monospace;
        background-color: #070B12;
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 8px;
        padding: 12px 16px;
        color: #38BDF8;
        font-size: 0.95rem;
        word-break: break-all;
        white-space: pre-wrap;
    }

    /* Metric cards */
    div[data-testid="stMetricValue"] {
        color: #00E5FF !important;
        font-family: 'Consolas', monospace;
    }

    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: #0F172A;
        padding: 6px;
        border-radius: 10px;
        border: 1px solid rgba(255, 255, 255, 0.05);
    }

    .stTabs [data-baseweb="tab"] {
        color: #94A3B8;
        border-radius: 8px;
        font-weight: 600;
        padding: 8px 16px;
    }

    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, rgba(0, 229, 255, 0.15) 0%, rgba(0, 245, 212, 0.15) 100%) !important;
        color: #00E5FF !important;
        border: 1px solid rgba(0, 229, 255, 0.4) !important;
    }

    /* File uploader custom style */
    div[data-testid="stFileUploader"] {
        background-color: #111827;
        border: 2px dashed rgba(0, 229, 255, 0.3);
        border-radius: 12px;
        padding: 1rem;
    }
    div[data-testid="stFileUploader"]:hover {
        border-color: #00E5FF;
    }

    /* Streamlit button */
    .stButton > button {
        background: linear-gradient(135deg, #00B4D8 0%, #0077B6 100%);
        color: #FFFFFF;
        font-weight: 700;
        border: none;
        border-radius: 8px;
        padding: 0.6rem 1.5rem;
        transition: all 0.3s ease;
        box-shadow: 0 4px 14px rgba(0, 180, 216, 0.3);
    }
    .stButton > button:hover {
        background: linear-gradient(135deg, #00E5FF 0%, #00B4D8 100%);
        box-shadow: 0 6px 20px rgba(0, 229, 255, 0.5);
        color: #070B12;
    }
    </style>
    """


def create_gauge_chart(score: int, title: str = "Threat Risk Index") -> go.Figure:
    """Generate a responsive, dark-mode cybersecurity semicircular gauge chart."""
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            number={"suffix": "/100", "font": {"size": 42, "color": "#FFFFFF", "family": "Consolas"}},
            title={"text": f"<b>{title}</b>", "font": {"size": 18, "color": "#94A3B8"}},
            gauge={
                "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "#475569", "tickfont": {"color": "#94A3B8"}},
                "bar": {"color": "#00E5FF", "thickness": 0.25},
                "bgcolor": "#1E293B",
                "borderwidth": 1,
                "bordercolor": "#334155",
                "steps": [
                    {"range": [0, 24], "color": "rgba(6, 214, 160, 0.25)"},
                    {"range": [24, 49], "color": "rgba(255, 183, 3, 0.25)"},
                    {"range": [49, 74], "color": "rgba(251, 133, 0, 0.25)"},
                    {"range": [74, 100], "color": "rgba(255, 51, 102, 0.35)"},
                ],
                "threshold": {
                    "line": {"color": "#FF3366", "width": 4},
                    "thickness": 0.75,
                    "value": score,
                },
            },
        )
    )

    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#E2E8F0"},
        height=260,
        margin=dict(l=20, r=20, t=50, b=20),
    )
    return fig


def create_breakdown_bar_chart(breakdown_items: List[Any]) -> go.Figure:
    """Generate a horizontal bar chart showing individual indicator point contributions."""
    if not breakdown_items:
        fig = go.Figure()
        fig.add_annotation(
            text="No threat indicators detected (Score: 0)",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False,
            font=dict(size=14, color="#06D6A0")
        )
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            height=200,
            margin=dict(l=10, r=10, t=20, b=20),
        )
        return fig

    titles = [item.title for item in breakdown_items]
    points = [item.points for item in breakdown_items]
    severities = [item.severity for item in breakdown_items]

    color_map = {
        "CRITICAL": "#FF3366",
        "HIGH": "#FB8500",
        "MEDIUM": "#FFB703",
        "LOW": "#06D6A0",
    }
    colors = [color_map.get(s, "#00E5FF") for s in severities]

    fig = go.Figure(
        go.Bar(
            x=points,
            y=titles,
            orientation="h",
            marker=dict(color=colors, line=dict(color="rgba(255,255,255,0.2)", width=1)),
            text=[f"+{p} pts ({s})" for p, s in zip(points, severities)],
            textposition="auto",
            textfont=dict(color="#FFFFFF", size=11),
        )
    )

    fig.update_layout(
        title=dict(text="<b>Risk Points by Detected Threat Vector</b>", font=dict(color="#E2E8F0", size=14)),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(
            title="Assigned Weight Points",
            gridcolor="#1E293B",
            color="#94A3B8",
            range=[0, max(points) + 15] if points else [0, 50],
        ),
        yaxis=dict(gridcolor="#1E293B", color="#E2E8F0", autorange="reversed"),
        height=max(180, len(breakdown_items) * 45),
        margin=dict(l=10, r=20, t=40, b=30),
    )
    return fig


def create_history_chart(history_records: List[Dict[str, Any]]) -> go.Figure:
    """Generate a timeline / comparison bar chart for session scan history."""
    if not history_records:
        fig = go.Figure()
        fig.add_annotation(
            text="No previous scans recorded in this session.",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False,
            font=dict(size=14, color="#94A3B8")
        )
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            height=220,
            margin=dict(l=10, r=10, t=20, b=20),
        )
        return fig

    df = pd.DataFrame(history_records)
    labels = [f"#{idx+1} {rec.get('display_name', 'Scan')[:20]}" for idx, rec in enumerate(history_records)]
    scores = df["score"].tolist()
    colors = [rec.get("color_hex", "#00E5FF") for rec in history_records]

    fig = go.Figure(
        go.Bar(
            x=labels,
            y=scores,
            marker=dict(color=colors, line=dict(color="#334155", width=1)),
            text=[f"{s}/100" for s in scores],
            textposition="outside",
            textfont=dict(color="#FFFFFF", size=11),
        )
    )

    fig.update_layout(
        title=dict(text="<b>Scan History Risk Score Comparison</b>", font=dict(color="#E2E8F0", size=14)),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(gridcolor="#1E293B", color="#94A3B8"),
        yaxis=dict(title="Risk Score", gridcolor="#1E293B", color="#94A3B8", range=[0, 115]),
        height=260,
        margin=dict(l=10, r=10, t=40, b=40),
    )
    return fig


def generate_qr_code_image(content: str) -> bytes:
    """Generate PNG bytes of a QR code encoding the provided content."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(content)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def get_demo_samples() -> Dict[str, Dict[str, Any]]:
    """Return preset cybersecurity test cases for quick demonstration and verification."""
    return {
        "Select a test sample...": {
            "content": "",
            "description": "Choose a preset payload to auto-generate and test instantly.",
        },
        "1. Legitimate Bank Portal (HTTPS Safe)": {
            "content": "https://www.chase.com/personal/banking",
            "description": "Standard banking domain with HTTPS, valid certificate structure, and zero phishing triggers.",
        },
        "2. Bare IP Phishing with Credential Harvester (Critical)": {
            "content": "http://192.168.1.105/account/login-verify.php?session=update",
            "description": "Uses insecure HTTP, bare IP address, and high-risk 'login' and 'verify' keywords.",
        },
        "3. Userinfo '@' Obfuscation Trick (Critical)": {
            "content": "https://www.google.com@evil-phishing-portal.net/security/auth",
            "description": "Deceptive URL using RFC userinfo '@' notation to trick users while navigating to an attacker server.",
        },
        "4. Executable Malware Payload (Critical)": {
            "content": "https://download-security-patch.top/client_setup.exe",
            "description": "Direct executable (.exe) payload delivery via QR code.",
        },
        "5. Punycode IDN Homograph Spoof (High)": {
            "content": "http://xn--gogle-pra.com/verify-account",
            "description": "Uses Punycode ('xn--') with Cyrillic lookalikes to impersonate a major search brand.",
        },
        "6. Public URL Shortener with Embedded Target (High)": {
            "content": "https://bit.ly/secure-login-portal",
            "description": "Shortened link concealing the destination domain from the user.",
        },
        "7. Brand Subdomain Spoof with Multiple Subdomains (High)": {
            "content": "https://paypal.com.account-update.security.attacker-site.org/signin",
            "description": "Chains 4 subdomains mimicking PayPal, but hosted on an unrelated registered domain.",
        },
        "8. Open Wi-Fi Network Configuration (Moderate)": {
            "content": "WIFI:T:nopass;S:Airport_Free_WiFi;P:;;",
            "description": "Unencrypted public Wi-Fi network configuration payload.",
        },
        "9. Plain Text Encoded Message (Low)": {
            "content": "Antigravity Project Review: Security Audit Passed.",
            "description": "Benign plain text payload without URL navigation vectors.",
        },
    }
