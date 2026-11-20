# QRShield AI – Intelligent QR Code Security Scanner 🛡️

[![Python Version](https://img.shields.io/badge/Python-3.11%20%7C%203.12-blue?logo=python)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.30+-FF4B4B?logo=streamlit)](https://streamlit.io)
[![OpenCV](https://img.shields.io/badge/OpenCV-Headless%20Vision-5C3EE8?logo=opencv)](https://opencv.org)
[![Security Rating](https://img.shields.io/badge/Security-Heuristic%2014--Vector-00F5D4)](https://github.com)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

--Website link--(https://qrshield-ai-6q4w.onrender.com)--
An intelligent, rule-based cybersecurity web application designed to defend users against **Quishing** (QR code phishing), malicious redirects, deceptive homoglyph domains, and mobile payload delivery. **QRShield AI** safely decodes QR codes in an isolated environment, decomposes URL anatomy, and computes a transparent 0–100 threat risk score before any user navigates to the destination.

---

## 🌟 Key Features

- **Multi-Format QR Ingestion:**
  - Drag-and-drop support for **PNG, JPG, JPEG, and WEBP**.
  - Advanced OpenCV computer vision pipeline with multi-stage fallback preprocessing (Grayscale, CLAHE adaptive equalization, and Otsu binarization) for low-light or noisy scans.
  - Multi-QR detection supporting multiple QR codes in a single image.
  - One-click **Demonstration Presets** for instant classroom/demonstration testing without external images.

- **Non-URL & Deep Content Classification:**
  - Automatic categorization of payloads into **URL, Plain Text, Wi-Fi Configuration, Email (`mailto:` / `MATMSG:`), Phone (`tel:`), SMS (`smsto:`), vCard Contacts, and Geo Coordinates**.
  - Specific risk analysis for non-URL payloads (e.g. unencrypted open Wi-Fi APs, automated SMS triggers, shell injection tokens).

- **Transparent 14-Vector Rule-Based Security Engine:**
  1. **Insecure HTTP Protocol** (`HTTP_INSECURE`): Plaintext transmission vulnerable to MITM.
  2. **Bare IP Address Host** (`IP_ADDRESS_HOST`): Raw IP evasion avoiding domain reputation feeds.
  3. **URL Shortening Obfuscation** (`URL_SHORTENER`): Known link compressors masking destinations (`bit.ly`, `tinyurl.com`, etc.).
  4. **Excessive Subdomain Nesting** (`EXCESSIVE_SUBDOMAINS`): Multi-tier domain chaining.
  5. **Abnormal URL Length** (`SUSPICIOUS_LENGTH`): Pushing domains off mobile viewports (>120 chars).
  6. **Userinfo `@` Symbol Trick** (`AT_SYMBOL_TRICK`): Browser routing trickery using RFC authority syntax.
  7. **Punycode / IDN Homographs** (`PUNYCODE_DOMAIN`): Internationalized domain spoofing (`xn--`).
  8. **Phishing & Credential Keywords** (`SUSPICIOUS_KEYWORDS`): Targeting passwords, logins, and accounts.
  9. **Unusual Custom Ports** (`UNUSUAL_PORT`): Non-standard service ports (:8443, :8888, :8000+).
  10. **URL Obfuscation & Evasion** (`OBFUSCATED_PATTERNS`): Double percent-encoding and directory traversal.
  11. **Malicious Executable Extensions** (`SUSPICIOUS_FILE_EXTENSION`): Direct binary delivery (`.exe`, `.apk`, `.scr`, `.bat`).
  12. **Brand Typosquatting Lookalikes** (`HOMOGRAPH_TYPOSQUATTING`): Glyph and character substitutions (`goog1e`, `paypa1`).
  13. **Embedded Open Redirects** (`EMBEDDED_REDIRECT`): Bouncing victims across legitimate domains.
  14. **Misleading Domain Structures** (`MISLEADING_HOSTNAME`): Brand-in-subdomain spoofing and hyphen-stuffed domains.

- **Explainable Weighted Risk Engine (0–100):**
  - **0–24: Low Risk** (🟢 Safe / Normal cyber hygiene)
  - **25–49: Moderate Risk** (🟡 Proceed with caution, unusual characteristics)
  - **50–74: High Risk** (🟠 Elevated threat, strong phishing indicators)
  - **75–100: Critical Risk** (🔴 Severe threat, abort navigation)
  - Attack synergy multiplier applied when multiple phishing indicators combine.

- **Threat Intelligence Integration:**
  - Optional external validation via **VirusTotal API v3** or **Google Safe Browsing API v4**.
  - Built-in **SSRF Protection** blocking private subnets, loopbacks, and non-HTTP lookups.
  - Operates seamlessly in **Local Analysis Mode** when no external API credentials are provided.

- **Auditing & Session History:**
  - Session-based scan records with timestamps, threat categories, and Plotly comparative risk score analytics.
  - One-click CSV export and history wiping.

---

## 🏛️ System Architecture

```text
QRShield-AI/
│
├── app.py                     # Streamlit frontend & interactive cybersecurity dashboard
├── requirements.txt           # Production dependencies (headless OpenCV, Plotly, Pandas)
├── README.md                  # Comprehensive documentation & deployment guide
├── .env.example               # Environment variables template
├── .gitignore                 # Version control exclusions
│
├── .streamlit/
│   └── config.toml            # Dark cybersecurity theme & server configuration
│
├── scanner/
│   ├── __init__.py            # Scanner package initialization
│   ├── decoder.py             # Computer vision QR decoding with adaptive preprocessing
│   ├── url_analyzer.py        # 14-point heuristic URL security engine & URL deconstruction
│   ├── risk_engine.py         # Modular weighted scoring model with attack synergy bonuses
│   ├── reputation.py          # Optional VirusTotal / Google Safe Browsing integration
│   └── validators.py          # Image integrity checks, SSRF prevention & HTML sanitization
│
├── utils/
│   ├── __init__.py            # Utility package initialization
│   └── helpers.py             # Plotly charts, preset generators & custom CSS styling
│
├── tests/
│   ├── __init__.py
│   ├── conftest.py            # Pytest environment & path configuration
│   ├── test_decoder.py        # Automated decoder test suite
│   ├── test_analyzer.py       # Heuristic rule validation test suite
│   ├── test_risk_engine.py    # Risk scoring & boundary condition test suite
│   └── test_validators.py     # Image validation, SSRF defense & sanitization test suite
│
└── assets/
    └── logo.png               # High-resolution vector-rendered cybersecurity shield logo
```

---

## 🚀 Quickstart Guide (Local Setup)

### 1. Prerequisites
- **Python 3.11+** installed on your system.
- Git (optional, for cloning).

### 2. Virtual Environment Setup

#### Windows (PowerShell):
```powershell
# Navigate into the project folder
cd QRShield-AI

# Create virtual environment
py -3.11 -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

#### macOS / Linux:
```bash
cd QRShield-AI
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Running the Application

Launch the Streamlit dashboard:
```powershell
streamlit run app.py
```

The application will launch automatically in your browser at `http://localhost:8501`.

---

## 🧪 Running Automated Unit Tests

QRShield AI features a comprehensive suite of **61 automated unit tests** covering valid/invalid QR decoding, plain text, Wi-Fi, SSRF prevention, all 14 security rules, risk score boundaries, and external API timeouts:

```powershell
# Execute pytest with verbose output
pytest -v
```

All 61 tests execute in under 1 second without requiring external network access.

---

## 🔑 Optional Threat Intelligence Configuration

The application operates in **Local Analysis Mode** by default. To enable external threat intelligence checks:

1. Copy `.env.example` to `.env`:
   ```powershell
   Copy-Item .env.example .env
   ```
2. Open `.env` and add your free VirusTotal or Google Safe Browsing API key:
   ```env
   # Optional: VirusTotal API v3
   VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

   # Optional: Google Safe Browsing v4
   SAFEBROWSING_API_KEY=your_google_safe_browsing_key_here
   ```
3. Restart Streamlit. The dashboard telemetry sidebar will update to reflect the active threat feed.

---

## 🌐 Render.com Free Tier Deployment Guide

QRShield AI is specifically engineered for frictionless deployment on **Render's Free Python Web Service**:

- **RAM Optimized:** Memory footprint stays under 180 MB (well below Render's 512 MB free tier ceiling).
- **Headless Vision:** Uses `opencv-python-headless` to eliminate the need for system-level GUI/X11 or ZBar libraries.
- **Stateless Design:** No permanent local file persistence required.

### Step-by-Step Render Deployment:

1. **Push to GitHub:**
   Commit the `QRShield-AI` repository to your GitHub account:
   ```bash
   git init
   git add .
   git commit -m "Initial commit of QRShield AI"
   git branch -M main
   git remote add origin https://github.com/<your-username>/QRShield-AI.git
   git push -u origin main
   ```

2. **Create New Web Service on Render:**
   - Log in to [Render Dashboard](https://dashboard.render.com/).
   - Click **New +** -> **Web Service**.
   - Connect your GitHub repository.

3. **Configure Service Settings:**
   - **Name:** `qrshield-ai`
   - **Environment:** `Python 3`
   - **Region:** Any region close to your users (e.g., Oregon, Frankfurt, Singapore).
   - **Branch:** `main`
   - **Build Command:**
     ```bash
     pip install -r requirements.txt
     ```
   - **Start Command:**
     ```bash
     streamlit run app.py --server.port $PORT --server.address 0.0.0.0 --server.headless true
     ```

4. **Environment Variables (Optional):**
   - Under the **Environment Variables** tab, add `VIRUSTOTAL_API_KEY` or `SAFEBROWSING_API_KEY` if you wish to enable external reputation checking.

5. **Deploy:**
   - Click **Create Web Service**. Render will build dependencies and start the app automatically.

---

## 🛡️ Security Design Principles

1. **No Automatic Navigation:** QRShield AI NEVER opens, visits, or automatically requests decoded destination URLs in the user's browser.
2. **No Automatic Execution:** Downloaded scripts or executables are never parsed or executed.
3. **SSRF Hardening:** URL validation blocks private IP subnets (RFC 1918), loopbacks, link-local addresses, and non-HTTP protocols prior to any external reputation queries.
4. **Output Sanitization:** Decoded contents and parameters are sanitized with HTML entity escaping to prevent cross-site scripting (XSS).
5. **Credential Protection:** API keys are read solely from environment variables and are never surfaced in client-side HTML or responses.

---

## ⚠️ Limitations & Responsible-Use Notice

- **Advisory Role:** QRShield AI is designed as a security auditing and education aid. An absence of threat indicators does not guarantee that a destination is 100% benign.
- **HTTPS Does Not Guarantee Safety:** Modern phishing kits frequently utilize legitimate, free SSL/TLS certificates (e.g., Let's Encrypt, Cloudflare).
- **Heuristic Indicators:** Single weak indicators (e.g., long URL query parameters from tracking systems) are evaluated within the weighted scoring engine and do not automatically label a website malicious.

---

## 🎓 Academic / Portfolio Attribution

**Developed as an advanced cybersecurity and computer vision demonstration project.**  
Suitable for B.Tech CSE (AIML / Cyber Security) capstone evaluations, technical research demonstrations, and portfolio showcases.
