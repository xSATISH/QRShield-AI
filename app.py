"""QRShield AI - Intelligent QR Code Security Scanner
Main Streamlit Application Dashboard.
"""

import datetime
import html
import io
import os
import sys
from typing import Optional

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

import pandas as pd
import streamlit as st
from PIL import Image
from dotenv import load_dotenv

# Load local .env if present
load_dotenv()

from scanner.validators import validate_image_file, sanitize_text
from scanner.decoder import QRDecoder, ContentType, QRScanResult
from scanner.url_analyzer import URLAnalyzer, URLAnalysisResult
from scanner.risk_engine import RiskEngine, RiskAssessment, RiskLevel
from scanner.reputation import ReputationChecker, ReputationResult
from utils.helpers import (
    create_gauge_chart,
    create_breakdown_bar_chart,
    create_history_chart,
    generate_qr_code_image,
    get_demo_samples,
    get_custom_css,
)

# =============================================================================
# Page Configuration & Theming
# =============================================================================

st.set_page_config(
    page_title="QRShield AI - Intelligent QR Code Security Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Inject Custom Cyber Aesthetics
st.markdown(get_custom_css(), unsafe_allow_html=True)

# Initialize Session State
if "history" not in st.session_state:
    st.session_state.history = []
if "current_scan" not in st.session_state:
    st.session_state.current_scan = None
if "selected_sample" not in st.session_state:
    st.session_state.selected_sample = "Select a test sample..."

# Core Singletons
decoder = QRDecoder()
url_analyzer = URLAnalyzer()
risk_engine = RiskEngine()
reputation_checker = ReputationChecker()

# =============================================================================
# Sidebar Navigation & System Telemetry
# =============================================================================

with st.sidebar:
    # Logo and Brand Branding
    logo_path = os.path.join(os.path.dirname(__file__), "assets", "logo.png")
    if os.path.exists(logo_path):
        st.image(logo_path, width=80)

    st.markdown("### **QRShield AI**")
    st.caption("Intelligent QR Code Threat Scanner")
    st.markdown("---")

    # Engine Status Indicators
    st.markdown("#### **System Telemetry**")
    st.markdown(
        """
        <div style="font-size: 0.85rem; line-height: 1.6; color: #94A3B8;">
            <div>● <b>Detection Engine:</b> <span style="color:#00F5D4;">Active (14 Rules)</span></div>
            <div>● <b>QR Decoder:</b> <span style="color:#00E5FF;">OpenCV Vision</span></div>
            <div>● <b>Parser:</b> <span style="color:#00F5D4;">RFC 3986 Standard</span></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Reputation Mode Status
    vt_active = bool(os.getenv("VIRUSTOTAL_API_KEY"))
    gsb_active = bool(os.getenv("SAFEBROWSING_API_KEY"))
    if vt_active:
        rep_status = '<span style="color:#06D6A0;">VirusTotal API v3</span>'
    elif gsb_active:
        rep_status = '<span style="color:#06D6A0;">Google Safe Browsing</span>'
    else:
        rep_status = '<span style="color:#FFB703;">Local Heuristic Mode</span>'

    st.markdown(
        f"""
        <div style="font-size: 0.85rem; margin-top: 6px; color: #94A3B8;">
            ● <b>Threat Intelligence:</b> {rep_status}
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("---")
    st.markdown("#### **Session Stats**")
    st.metric(label="Total Scans", value=len(st.session_state.history))

    st.markdown("---")
    st.markdown(
        """
        <div style="font-size: 0.8rem; color: #64748B;">
            <b>Security Notice:</b> QRShield AI operates in an isolated sandbox. 
            URLs are analyzed passively and are <b>never executed or navigated</b> automatically.
        </div>
        """,
        unsafe_allow_html=True,
    )

# =============================================================================
# Main Header
# =============================================================================

st.markdown(
    """
    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem;">
        <div>
            <div class="cyber-title">QRShield AI</div>
            <div class="cyber-subtitle">Next-Generation QR Code Threat Detection & Phishing Defense Platform</div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# Tabs
tab_scanner, tab_analysis, tab_history, tab_about = st.tabs(
    ["🔍 Scanner", "🛡️ Security Analysis", "📜 Scan History", "ℹ️ About & Threat Intel"]
)


# =============================================================================
# TAB 1: SCANNER
# =============================================================================

with tab_scanner:
    st.markdown("### **Upload & Decode QR Code**")
    st.write("Upload an image containing a QR code or choose a demonstration preset to inspect for security threats.")

    col_upload, col_preview = st.columns([1.1, 0.9])

    uploaded_image_bytes = None
    uploaded_filename = ""

    with col_upload:
        # Demo Presets Dropdown
        demo_samples = get_demo_samples()
        sample_choice = st.selectbox(
            "⚡ Quick Test: Select Demonstration Preset",
            options=list(demo_samples.keys()),
            index=0,
            help="Choose a pre-constructed QR security test case to evaluate detection capabilities instantly.",
        )

        sample_info = demo_samples[sample_choice]
        if sample_choice != "Select a test sample..." and sample_info["content"]:
            st.info(f"**Preset Selected:** {sample_info['description']}")
            uploaded_image_bytes = generate_qr_code_image(sample_info["content"])
            uploaded_filename = f"{sample_choice.split()[0].replace('.', '')}_demo.png"

        # File Uploader
        uploaded_file = st.file_uploader(
            "Or drag and drop an image file (PNG, JPG, JPEG, WEBP)",
            type=["png", "jpg", "jpeg", "webp"],
            help="Upload a screenshot or photo of any QR code for automated security auditing.",
        )

        if uploaded_file is not None:
            uploaded_image_bytes = uploaded_file.getvalue()
            uploaded_filename = uploaded_file.name

        scan_btn = st.button("🚀 Scan & Analyze QR Code", use_container_width=True)

    with col_preview:
        st.markdown("#### **Image Inspection Preview**")
        if uploaded_image_bytes:
            # Validate image format and dimensions first
            is_valid_img, img_err, img_meta = validate_image_file(uploaded_image_bytes, uploaded_filename)
            if is_valid_img:
                st.image(uploaded_image_bytes, caption=f"{uploaded_filename} ({img_meta['width']}x{img_meta['height']}px)", use_container_width=True)
            else:
                st.error(f"⚠️ Image validation failed: {img_err}")
                uploaded_image_bytes = None
        else:
            st.markdown(
                """
                <div style="border: 2px dashed #1E293B; border-radius: 12px; padding: 40px; text-align: center; color: #64748B;">
                    No QR code image uploaded yet.<br>
                    <span style="font-size: 0.85rem;">Upload an image on the left or select a preset to begin.</span>
                </div>
                """,
                unsafe_allow_html=True,
            )

    # Process Scan
    if scan_btn and uploaded_image_bytes:
        with st.spinner("Executing computer vision decoding and threat evaluation..."):
            # 1. Decode QR Code
            qr_results, decode_err = decoder.decode_image_bytes(uploaded_image_bytes)

            if decode_err or not qr_results:
                st.error(f"❌ {decode_err or 'No valid QR code detected in the image.'}")
                st.session_state.current_scan = None
            else:
                # Select primary QR code (support first or multiple)
                selected_result = qr_results[0]
                multi_count = len(qr_results)

                # 2. Analyze Security Properties
                if selected_result.is_url:
                    url_analysis = url_analyzer.analyze(selected_result.raw_content)
                    risk_assessment = risk_engine.assess_url(url_analysis)
                    reputation_result = reputation_checker.check_url(selected_result.raw_content)
                else:
                    url_analysis = None
                    risk_assessment = risk_engine.assess_non_url(selected_result)
                    reputation_result = None

                # Store current scan
                scan_record = {
                    "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "filename": uploaded_filename,
                    "qr_result": selected_result,
                    "url_analysis": url_analysis,
                    "risk_assessment": risk_assessment,
                    "reputation": reputation_result,
                    "multi_count": multi_count,
                    "display_name": selected_result.raw_content[:30],
                    "score": risk_assessment.score,
                    "level": risk_assessment.level.value,
                    "color_hex": risk_assessment.color_hex,
                    "indicators_count": len(risk_assessment.indicators),
                }

                st.session_state.current_scan = scan_record
                # Add to history
                st.session_state.history.append(scan_record)

    # Display Scan Results if present
    if st.session_state.current_scan:
        scan = st.session_state.current_scan
        qr_res: QRScanResult = scan["qr_result"]
        risk: RiskAssessment = scan["risk_assessment"]
        url_ana: Optional[URLAnalysisResult] = scan["url_analysis"]
        rep: Optional[ReputationResult] = scan["reputation"]

        st.markdown("---")
        st.markdown("### **Scan Summary Results**")

        if scan["multi_count"] > 1:
            st.info(f"ℹ️ Multi-QR detection: Detected {scan['multi_count']} QR codes in this image. Showing primary code.")

        # Top Metric Badges
        col_m1, col_m2, col_m3, col_m4 = st.columns(4)

        with col_m1:
            st.markdown(
                f"""
                <div class="cyber-card" style="text-align: center;">
                    <div style="color: #94A3B8; font-size: 0.85rem; font-weight: 600;">PAYLOAD TYPE</div>
                    <div style="color: #00E5FF; font-size: 1.3rem; font-weight: 800; margin-top: 4px;">{qr_res.content_type.value}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with col_m2:
            badge_class = {
                RiskLevel.LOW: "badge-low",
                RiskLevel.MODERATE: "badge-moderate",
                RiskLevel.HIGH: "badge-high",
                RiskLevel.CRITICAL: "badge-critical",
            }.get(risk.level, "badge-low")

            st.markdown(
                f"""
                <div class="cyber-card" style="text-align: center;">
                    <div style="color: #94A3B8; font-size: 0.85rem; font-weight: 600;">THREAT LEVEL</div>
                    <div style="margin-top: 6px;"><span class="{badge_class}">{risk.level.value}</span></div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with col_m3:
            st.markdown(
                f"""
                <div class="cyber-card" style="text-align: center;">
                    <div style="color: #94A3B8; font-size: 0.85rem; font-weight: 600;">RISK SCORE</div>
                    <div style="color: {risk.color_hex}; font-size: 1.5rem; font-weight: 800; font-family: Consolas;">{risk.score} / 100</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with col_m4:
            st.markdown(
                f"""
                <div class="cyber-card" style="text-align: center;">
                    <div style="color: #94A3B8; font-size: 0.85rem; font-weight: 600;">THREAT INDICATORS</div>
                    <div style="color: #FFFFFF; font-size: 1.5rem; font-weight: 800; font-family: Consolas;">{len(risk.indicators)} Detected</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        # Decoded Content Card
        st.markdown("#### **Extracted QR Code Content**")
        safe_raw_content = sanitize_text(qr_res.raw_content)
        st.markdown(
            f"""
            <div class="payload-display">{safe_raw_content}</div>
            """,
            unsafe_allow_html=True,
        )

        # Action Guideline Banner
        banner_border_color = risk.color_hex
        st.markdown(
            f"""
            <div style="border-left: 4px solid {banner_border_color}; background-color: #111827; border-radius: 8px; padding: 14px 18px; margin-top: 14px;">
                <div style="color: {banner_border_color}; font-weight: 700; font-size: 1rem;">Recommended Action:</div>
                <div style="color: #E2E8F0; font-size: 0.95rem; margin-top: 4px;">{html.escape(risk.action_recommendation)}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Non-URL Structured Details (if applicable)
        if not qr_res.is_url and qr_res.details:
            st.markdown("#### **Payload Metadata**")
            detail_cols = st.columns(len(qr_res.details))
            for c, (k, v) in zip(detail_cols, qr_res.details.items()):
                with c:
                    st.metric(label=k.replace("_", " ").title(), value=str(v))


# =============================================================================
# TAB 2: DETAILED SECURITY ANALYSIS
# =============================================================================

with tab_analysis:
    st.markdown("### **Deep Security & Threat Vector Analysis**")

    if not st.session_state.current_scan:
        st.info("💡 Please scan a QR code in the **Scanner** tab first to view deep security telemetry.")
    else:
        scan = st.session_state.current_scan
        qr_res: QRScanResult = scan["qr_result"]
        risk: RiskAssessment = scan["risk_assessment"]
        url_ana: Optional[URLAnalysisResult] = scan["url_analysis"]
        rep: Optional[ReputationResult] = scan["reputation"]

        col_gauge, col_breakdown = st.columns([1, 1.2])

        with col_gauge:
            st.plotly_chart(create_gauge_chart(risk.score), use_container_width=True)

        with col_breakdown:
            st.plotly_chart(create_breakdown_bar_chart(risk.breakdown), use_container_width=True)

        st.markdown("---")

        # URL Anatomy Breakdown (if URL)
        if url_ana and url_ana.anatomy:
            anat = url_ana.anatomy
            st.markdown("#### **URL Anatomy Deconstruction**")

            anat_col1, anat_col2, anat_col3 = st.columns(3)
            with anat_col1:
                st.markdown(f"**Protocol:** `{'HTTPS (Encrypted)' if anat.is_https else 'HTTP (Insecure)'}`")
                st.markdown(f"**Registered Domain:** `{html.escape(anat.registered_domain)}`")
                st.markdown(f"**Subdomain:** `{html.escape(anat.subdomain or '(None)')}`")

            with anat_col2:
                st.markdown(f"**Port:** `{anat.port or ('443 (Default HTTPS)' if anat.is_https else '80 (Default HTTP)')}`")
                st.markdown(f"**Path:** `{html.escape(anat.path or '/')}`")
                st.markdown(f"**Fragment:** `{html.escape(anat.fragment or '(None)')}`")

            with anat_col3:
                param_count = len(anat.query_params)
                st.markdown(f"**Query Parameters:** `{param_count}`")
                if param_count > 0:
                    for k, v in list(anat.query_params.items())[:3]:
                        st.caption(f"• `{html.escape(k)}` = `{html.escape(str(v[0])[:30])}`")

            st.markdown("---")

        # Detected Threat Indicators
        st.markdown("#### **Detected Threat Indicators & Heuristics**")
        if not risk.indicators:
            st.success("✅ Clean Scan: No malicious manipulation indicators or phishing heuristics were identified.")
        else:
            for ind in risk.indicators:
                sev_color = {
                    "CRITICAL": "#FF3366",
                    "HIGH": "#FB8500",
                    "MEDIUM": "#FFB703",
                    "LOW": "#06D6A0",
                }.get(ind.severity, "#00E5FF")

                with st.expander(f"⚠️ [{ind.severity}] {ind.title} — {ind.category}", expanded=True):
                    st.markdown(f"**Description:** {ind.description}")
                    st.markdown(f"**Evidence:** `{html.escape(ind.evidence)}`")
                    st.markdown(f"**Mitigation Advice:** {ind.recommendation}")

        st.markdown("---")

        # External Reputation Intelligence Section
        st.markdown("#### **External Threat Intelligence Status**")
        if rep:
            col_rep1, col_rep2 = st.columns([1, 2])
            with col_rep1:
                st.metric("Service Provider", rep.provider)
                st.metric("Reputation Status", rep.status)
                if rep.total_engines > 0:
                    st.metric("Malicious Detections", f"{rep.malicious_count} / {rep.total_engines} Engines")

            with col_rep2:
                st.markdown(f"**Summary:** {rep.summary}")
                if rep.permalink:
                    st.markdown(f"🔗 [View Full VirusTotal Analysis Report]({rep.permalink})")
                st.caption(f"📌 **Notice:** {rep.disclaimer}")
        else:
            st.markdown("External reputation checks apply to web URL destinations.")


# =============================================================================
# TAB 3: SCAN HISTORY
# =============================================================================

with tab_history:
    st.markdown("### **Session Scan History**")
    st.caption("Review previous scans, compare threat ratings, and export reports.")

    if not st.session_state.history:
        st.info("ℹ️ No scans recorded in this session. Scan a QR code to populate the audit log.")
    else:
        # History Graph
        st.plotly_chart(create_history_chart(st.session_state.history), use_container_width=True)

        # Tabular View
        table_rows = []
        for idx, rec in enumerate(st.session_state.history):
            qr_item: QRScanResult = rec["qr_result"]
            risk_item: RiskAssessment = rec["risk_assessment"]
            table_rows.append({
                "Scan #": idx + 1,
                "Timestamp": rec["timestamp"],
                "Type": qr_item.content_type.value,
                "Content / URL (Excerpt)": qr_item.raw_content[:45] + ("..." if len(qr_item.raw_content) > 45 else ""),
                "Risk Score": f"{risk_item.score} / 100",
                "Risk Level": risk_item.level.value,
                "Indicators": len(risk_item.indicators),
            })

        df_history = pd.DataFrame(table_rows)
        st.dataframe(df_history, use_container_width=True, hide_index=True)

        col_hist_action1, col_hist_action2 = st.columns([1, 4])
        with col_hist_action1:
            if st.button("🗑️ Clear Session History", use_container_width=True):
                st.session_state.history = []
                st.session_state.current_scan = None
                st.rerun()

        with col_hist_action2:
            csv_data = df_history.to_csv(index=False).encode("utf-8")
            st.download_button(
                "📥 Export History (CSV)",
                data=csv_data,
                file_name="qrshield_scan_history.csv",
                mime="text/csv",
            )


# =============================================================================
# TAB 4: ABOUT & THREAT INTEL
# =============================================================================

with tab_about:
    st.markdown("### **About QRShield AI**")
    st.markdown(
        """
        **QRShield AI** is an intelligent cybersecurity auditing platform engineered to combat the rapid surge in 
        **Quishing (QR code phishing)** and mobile threat delivery.

        When individuals scan physical or digital QR codes using mobile devices, small screens and truncated browser address bars 
        frequently conceal deceptive domain structures, disguised payloads, and malicious redirects. QRShield AI decodes the payload 
        without executing it, subjects it to a 14-point heuristic security engine, and evaluates potential threat vectors before the user navigates.
        """
    )

    st.markdown("---")
    st.markdown("### **Common Quishing & QR Threat Vectors Analyzed**")

    col_t1, col_t2 = st.columns(2)

    with col_t1:
        st.markdown(
            """
            #### 1. Bare IP & Port Bypasses
            Phishing kits frequently host fake banking or credential portals directly on raw IP addresses (e.g. `http://185.x.x.x:8080/login`) 
            to bypass newly registered domain filters and DNS-based blacklists.

            #### 2. RFC Userinfo '@' Obfuscation
            Standard URI syntax treats everything before the `@` symbol as user authentication metadata. In links like `https://google.com@evil.com`, 
            the browser ignores `google.com` and connects straight to `evil.com`.

            #### 3. IDN Homograph & Punycode Attacks
            Attackers register domains using international Cyrillic or Greek characters (`xn--`) that visually mirror Latin letters 
            (e.g., swapping Latin 'a' with Cyrillic 'а') to construct visually identical brand clones.
            """
        )

    with col_t2:
        st.markdown(
            """
            #### 4. URL Shortener Masking
            Shorteners like `bit.ly` or `tinyurl.com` compress URLs to save space on QR codes, but completely obscure the real destination 
            from the user until after they have navigated.

            #### 5. Open Redirects & Parameter Embedding
            Attackers abuse legitimate domains that allow unvalidated query parameter redirection (e.g. `?dest=`, `?url=`), 
            deceiving victims into trusting the initial brand domain before bouncing them to a phishing page.

            #### 6. Executable Payloads & Rogue Wi-Fi
            QR codes can encode direct download links to `.apk`, `.exe`, or script payloads, or automatically connect victim devices to unencrypted rogue Wi-Fi access points.
            """
        )

    st.markdown("---")
    st.markdown("### **Technology Architecture**")
    st.markdown(
        """
        - **Computer Vision:** OpenCV `cv2.QRCodeDetector` with multi-stage grayscale, CLAHE, and Otsu contrast enhancement.
        - **Frontend Interface:** Streamlit 1.30+ with custom dark cybersecurity glassmorphism styling.
        - **Visual Analytics:** Plotly for dynamic semicircular risk meters and horizontal threat factor charts.
        - **URL Security Engine:** Pure Python rule-based deterministic heuristic analyzer adhering to RFC 3986 and SSRF validation standards.
        - **Threat Intelligence:** Optional integration with VirusTotal API v3 and Google Safe Browsing API v4.
        """
    )

    st.markdown("---")
    st.markdown("### **Responsible Use & Operational Limitations**")
    st.warning(
        """
        **Educational and Defensive Tool Notice:**  
        - QRShield AI is designed to assist security analysts, developers, and users in spotting threat indicators.
        - **No automated scanner guarantees 100% safety:** Absence of an alert does not prove a website is completely benign. Cybercriminals frequently stand up brand-new phishing domains hours before launching a campaign.
        - **HTTPS does not equal safe:** A valid SSL/TLS certificate merely encrypts transit data; millions of phishing websites possess free HTTPS certificates.
        - Always exercise personal cyber vigilance when entering sensitive information.
        """
    )
