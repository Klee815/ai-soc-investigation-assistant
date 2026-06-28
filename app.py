import streamlit as st
import tempfile
import pandas as pd
import plotly.express as px

from src.parser import load_logs
from src.analyzer import (
    detect_brute_force,
    detect_powershell,
    detect_file_access,
)
from src.report_generator import generate_report
from src.mitre_mapper import get_mitre_info

st.set_page_config(
    page_title="AI SOC Investigation Assistant",
    page_icon="🛡️",
    layout="wide",
)

# ---------------------------------------------------
# Header
# ---------------------------------------------------

st.title("🛡️ AI SOC Investigation Assistant")

st.sidebar.title("Navigation")
st.sidebar.markdown("""
### Dashboard

- Upload Security Logs
- Threat Detection
- MITRE ATT&CK
- Incident Reports

---

Version 2.0
""")

uploaded_file = st.file_uploader(
    "Upload Security Log (.csv)",
    type=["csv"]
)

# ---------------------------------------------------
# Main Application
# ---------------------------------------------------

if uploaded_file:
    tab1, tab2, tab3, tab4 = st.tabs([
    "📊 Overview",
    "📜 Logs",
    "🎯 MITRE",
    "📄 Reports"
])

    with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
        tmp.write(uploaded_file.getvalue())
        temp_path = tmp.name

    logs = load_logs(temp_path)

# NEW CODE STARTS HERE
logs = load_logs(temp_path)

    search_ip = st.text_input(
        "🔍 Search by Source IP",
        placeholder="Example: 192.168.1.20"
    )

    if search_ip:
        logs = logs[
            logs["ip"].str.contains(search_ip, case=False, na=False)
        ]
# NEW CODE ENDS HERE

detections = [
    detect_brute_force(logs),
    detect_powershell(logs),
    detect_file_access(logs),
]
detections = [d for d in detections if d]


    # ---------------------------------------------------
    # Security Overview
    # ---------------------------------------------------

    high = sum(d["severity"] == "High" for d in detections)
    medium = sum(d["severity"] == "Medium" for d in detections)
    low = sum(d["severity"] == "Low" for d in detections)

    with tab1:

        st.header("Security Overview")

    c1, c2, c3, c4, c5 = st.columns(5)

    c1.metric("🔴 High", high)
    c2.metric("🟡 Medium", medium)
    c3.metric("🟢 Low", low)
    c4.metric("📄 Events", len(logs))
    c5.metric("🌍 Source IPs", logs["ip"].nunique())

    st.divider()

    # ---------------------------------------------------
    # Logs
    # ---------------------------------------------------

    with tab2:

        st.header("Security Logs")

    st.dataframe(
        logs,
        use_container_width=True
    )
    st.dataframe(logs, use_container_width=True)

    st.divider()

    # ---------------------------------------------------
    # Charts
    # ---------------------------------------------------

    left, right = st.columns(2)

    with left:

        st.subheader("Alert Severity")

        severity_df = (
            pd.DataFrame(detections)["severity"]
            .value_counts()
            .reset_index()
        )

        severity_df.columns = ["Severity", "Count"]

        fig = px.pie(
            severity_df,
            values="Count",
            names="Severity",
        )

        st.plotly_chart(fig, use_container_width=True)

    with right:

        st.subheader("Events by Source IP")

        ip_df = (
            logs["ip"]
            .value_counts()
            .reset_index()
        )

        ip_df.columns = ["IP Address", "Events"]

        fig2 = px.bar(
            ip_df,
            x="IP Address",
            y="Events",
        )

        st.plotly_chart(fig2, use_container_width=True)

    st.divider()

    # ---------------------------------------------------
    # MITRE
    # ---------------------------------------------------

    with tab3:

        st.header("MITRE ATT&CK Mapping")

    mitre = []

    for detection in detections:

        mapping = get_mitre_info(detection["attack"])

        mitre.append({
            "Attack": detection["attack"],
            "Technique": mapping["technique"],
            "Name": mapping["name"],
        })

    st.dataframe(
        pd.DataFrame(mitre),
        use_container_width=True,
        hide_index=True,
    )

    st.divider()

    # ---------------------------------------------------
    # Reports
    # ---------------------------------------------------

    with tab4:

        st.header("Incident Reports")

    report = ""

    for detection in detections:

        report += generate_report(detection)
        report += "\n\n"

        with st.expander(detection["attack"]):
            st.code(generate_report(detection))

    st.download_button(
        "📥 Download Incident Report",
        report,
        "incident_report.txt",
        "text/plain",
    )