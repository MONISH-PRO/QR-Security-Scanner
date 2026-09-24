import streamlit as st
import cv2
import pandas as pd
import numpy as np
import os

from url_analyzer import analyze_url
from scan_history import save_scan


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="QR Code Security Scanner",
    page_icon="🔐",
    layout="wide"
)


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
    <style>

    .main-title {
        font-size: 42px;
        font-weight: bold;
        text-align: center;
        margin-bottom: 5px;
    }

    .subtitle {
        text-align: center;
        font-size: 18px;
        margin-bottom: 30px;
    }

    .result-box {
        padding: 20px;
        border-radius: 10px;
        border: 1px solid #cccccc;
        margin-top: 20px;
    }

    .risk-score {
        font-size: 30px;
        font-weight: bold;
        text-align: center;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# TITLE
# ============================================================

st.markdown(
    '<div class="main-title">🔐 QR CODE SECURITY SCANNER</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">Cybersecurity-based QR code and URL analysis</div>',
    unsafe_allow_html=True
)


# ============================================================
# QR DECODER
# ============================================================

def decode_qr_image(image_bytes):

    # Convert image bytes into NumPy array
    image_array = np.frombuffer(
        image_bytes,
        dtype=np.uint8
    )

    # Convert NumPy array into OpenCV image
    image = cv2.imdecode(
        image_array,
        cv2.IMREAD_COLOR
    )

    if image is None:
        return None

    detector = cv2.QRCodeDetector()

    # Try single QR code
    data, points, _ = detector.detectAndDecode(
        image
    )

    if data:
        return data

    # Try multiple QR codes
    try:

        success, decoded_info, points, _ = (
            detector.detectAndDecodeMulti(
                image
            )
        )

        if success and decoded_info:

            for item in decoded_info:

                if item:
                    return item

    except Exception:
        pass

    return None


# ============================================================
# SECURITY ANALYSIS
# ============================================================

def analyze_qr_content(data):

    st.subheader("🔍 QR Code Detected")

    st.write("**QR Content:**")

    st.code(
        data,
        language="text"
    )

    # Check whether QR contains a URL
    if data.startswith("http://") or data.startswith("https://"):

        risk_score, reasons, status = analyze_url(data)

        st.subheader("🛡️ Security Analysis")

        for reason in reasons:

            if reason.startswith("⚠"):

                st.warning(reason)

            else:

                st.success(reason)

        st.markdown("---")

        st.metric(
            "Risk Score",
            f"{risk_score}/100"
        )

        st.progress(
            risk_score
        )

        # Security status
        if status == "NO INDICATORS DETECTED":

            st.success(
                "Security Status: NO INDICATORS DETECTED"
            )

        elif status == "SUSPICIOUS":

            st.warning(
                "Security Status: SUSPICIOUS"
            )

        else:

            st.error(
                "Security Status: DANGEROUS"
            )

        # Save scan
        save_scan(
            data,
            risk_score,
            status
        )

        st.info(
            "Note: This result is based on the security rules "
            "implemented in this project. It does not guarantee "
            "that a website is completely safe or malicious."
        )

    else:

        st.info(
            "This QR code contains text rather than a URL."
        )


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title("🔐 QR Scanner")

page = st.sidebar.radio(
    "Select Option",
    [
        "Scan QR",
        "Scan History",
        "Statistics"
    ]
)


# ============================================================
# SCAN QR PAGE
# ============================================================

if page == "Scan QR":

    st.header("📷 Scan QR Code")

    tab1, tab2 = st.tabs(
        [
            "📁 Upload QR Image",
            "📷 Use Camera"
        ]
    )


    # ========================================================
    # UPLOAD IMAGE
    # ========================================================

    with tab1:

        uploaded_file = st.file_uploader(
            "Upload a QR code image",
            type=[
                "png",
                "jpg",
                "jpeg"
            ]
        )

        if uploaded_file:

            image_bytes = uploaded_file.getvalue()

            st.image(
                image_bytes,
                caption="Uploaded QR Code",
                width=300
            )

            if st.button(
                "🔍 Scan Uploaded QR",
                type="primary"
            ):

                data = decode_qr_image(
                    image_bytes
                )

                if data:

                    analyze_qr_content(
                        data
                    )

                else:

                    st.error(
                        "❌ No QR code was detected in this image."
                    )


    # ========================================================
    # CAMERA
    # ========================================================

    with tab2:

        st.write(
            "Allow camera permission when your browser asks."
        )

        camera_image = st.camera_input(
            "Take a picture of the QR code"
        )

        if camera_image:

            image_bytes = camera_image.getvalue()

            st.image(
                image_bytes,
                caption="Camera Image",
                width=300
            )

            if st.button(
                "🔍 Scan Camera QR",
                type="primary"
            ):

                data = decode_qr_image(
                    image_bytes
                )

                if data:

                    analyze_qr_content(
                        data
                    )

                else:

                    st.error(
                        "❌ No QR code was detected in the camera image."
                    )


# ============================================================
# SCAN HISTORY
# ============================================================

elif page == "Scan History":

    st.header("📋 Scan History")

    history_file = "scan_history.csv"

    if os.path.exists(history_file):

        try:

            df = pd.read_csv(
                history_file
            )

            if len(df) > 0:

                st.dataframe(
                    df,
                    use_container_width=True
                )

            else:

                st.info(
                    "No scan history available."
                )

        except Exception as error:

            st.error(
                f"Unable to read scan history: {error}"
            )

    else:

        st.info(
            "No scan history found."
        )

    st.markdown("---")

    if st.button(
        "🗑️ Clear Scan History"
    ):

        try:

            with open(
                history_file,
                "w",
                encoding="utf-8"
            ) as file:

                file.write(
                    "Date & Time,QR Content,Risk Score,Status\n"
                )

            st.success(
                "Scan history cleared successfully."
            )

            st.rerun()

        except Exception as error:

            st.error(
                f"Unable to clear history: {error}"
            )


# ============================================================
# STATISTICS
# ============================================================

elif page == "Statistics":

    st.header("📊 Scan Statistics")

    history_file = "scan_history.csv"

    total = 0
    safe = 0
    suspicious = 0
    dangerous = 0

    if os.path.exists(history_file):

        try:

            df = pd.read_csv(
                history_file
            )

            total = len(df)

            if total > 0:

                safe = (
                    df["Status"]
                    .astype(str)
                    .str.contains(
                        "NO INDICATORS DETECTED"
                    )
                    .sum()
                )

                suspicious = (
                    df["Status"]
                    .astype(str)
                    .str.contains(
                        "SUSPICIOUS"
                    )
                    .sum()
                )

                dangerous = (
                    df["Status"]
                    .astype(str)
                    .str.contains(
                        "DANGEROUS"
                    )
                    .sum()
                )

        except Exception:
            pass

    col1, col2, col3, col4 = st.columns(4)

    with col1:

        st.metric(
            "Total Scans",
            total
        )

    with col2:

        st.metric(
            "No Indicators",
            safe
        )

    with col3:

        st.metric(
            "Suspicious",
            suspicious
        )

    with col4:

        st.metric(
            "Dangerous",
            dangerous
        )


# ============================================================
# FOOTER
# ============================================================

st.markdown("---")

st.caption(
    "QR Security Scanner | Python Cybersecurity Project"
)