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
from src.mitre_mapper import get_mitre_info
from src.report_generator import generate_report


# ----------------------------------------------------
# Page Configuration
# ----------------------------------------------------

st.set_page_config(
    page_title="AI SOC Investigation Assistant",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ AI SOC Investigation Assistant")

st.sidebar.title("Navigation")
st.sidebar.markdown("""
### Dashboard

- Upload Security Logs
- Threat Detection
- MITRE ATT&CK
- Incident Reports

---

Version 3.0
""")

uploaded_file = st.file_uploader(
    "Upload Security Log (.csv)",
    type=["csv"]
)

# ----------------------------------------------------
# Main Application
# ----------------------------------------------------

if uploaded_file:

    # Create tabs
    tab1, tab2, tab3, tab4 = st.tabs([
        "📊 Overview",
        "📜 Logs",
        "🎯 MITRE",
        "📄 Reports"
    ])

    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
        tmp.write(uploaded_file.getvalue())
        temp_path = tmp.name

    # Load CSV
    logs = load_logs(temp_path)

    if logs is None:
        st.error("Unable to load log file.")
        st.stop()

    # Search by IP
    search_ip = st.text_input(
        "🔍 Search Source IP",
        placeholder="Example: 192.168.1.20"
    )

    if search_ip:
        logs = logs[
            logs["ip"].str.contains(
                search_ip,
                case=False,
                na=False
            )
        ]
    # ----------------------------------------
    # Detect Security Events
    # ----------------------------------------

    detections = [
        detect_brute_force(logs),
        detect_powershell(logs),
        detect_file_access(logs),
    ]

    # Remove None values
    detections = [d for d in detections if d]

    # Severity Filter
    severity_filter = st.multiselect(
        "Filter Severity",
        ["High", "Medium", "Low"],
        default=["High", "Medium", "Low"],
    )

    detections = [
        d for d in detections
        if d["severity"] in severity_filter
    ]

    # Count alerts
    high = sum(
        d["severity"] == "High"
        for d in detections
    )

    medium = sum(
        d["severity"] == "Medium"
        for d in detections
    )

    low = sum(
        d["severity"] == "Low"
        for d in detections
    )

    # ----------------------------------------
    # Overview Tab
    # ----------------------------------------

    with tab1:

        st.header("Security Overview")

        c1, c2, c3, c4, c5 = st.columns(5)

        c1.metric("🔴 High", high)
        c2.metric("🟡 Medium", medium)
        c3.metric("🟢 Low", low)
        c4.metric("📄 Events", len(logs))
        c5.metric("🌍 Source IPs", logs["ip"].nunique())

        st.divider()
        st.subheader("🚨 Threat Summary")

        if detections:
            for detection in detections:
                st.warning(
                    f"**{detection['attack']}** ({detection['severity']})\n\n"
                    f"{detection['description']}"
                )
        else:
            st.success("No suspicious activity detected.")
       

    if detections:

            st.success(
                f"Detected {len(detections)} security event(s)."
            )

    else:

            st.info("No suspicious activity detected.")
    # ----------------------------------------
    # Logs Tab
    # ----------------------------------------

    with tab2:

        st.header("Security Logs")

        st.dataframe(
            logs,
            use_container_width=True
        )
    # ----------------------------------------
    # Charts
    # ----------------------------------------

    with tab1:

        left, right = st.columns(2)

        with left:

            st.subheader("Alert Severity")

            if detections:

                severity_df = (
                    pd.DataFrame(detections)["severity"]
                    .value_counts()
                    .reset_index()
                )

                severity_df.columns = [
                    "Severity",
                    "Count"
                ]

                fig = px.pie(
                    severity_df,
                    values="Count",
                    names="Severity",
                    title="Alert Severity"
                )

                st.plotly_chart(
                    fig,
                    use_container_width=True
                )

        with right:

            st.subheader("Events by Source IP")

            ip_df = (
                logs["ip"]
                .value_counts()
                .reset_index()
            )

            ip_df.columns = [
                "IP Address",
                "Events"
            ]

            fig2 = px.bar(
                ip_df,
                x="IP Address",
                y="Events",
                title="Events by Source IP"
            )

            st.plotly_chart(
                fig2,
                use_container_width=True
            )
    # ----------------------------------------
    # Charts
    # ----------------------------------------

    with tab1:

        st.divider()

        left, right = st.columns(2)

        with left:

            st.subheader("Alert Severity")

            if detections:

                severity_df = (
                    pd.DataFrame(detections)["severity"]
                    .value_counts()
                    .reset_index()
                )

                severity_df.columns = [
                    "Severity",
                    "Count",
                ]

                fig = px.pie(
                    severity_df,
                    values="Count",
                    names="Severity",
                    hole=0.4,
                )

                st.plotly_chart(
                    fig,
                    use_container_width=True,
                )

        with right:

            st.subheader("Events by Source IP")

            ip_df = (
                logs["ip"]
                .value_counts()
                .reset_index()
            )

            ip_df.columns = [
                "IP Address",
                "Events",
            ]

            fig2 = px.bar(
                ip_df,
                x="IP Address",
                y="Events",
            )

            st.plotly_chart(
                fig2,
                use_container_width=True,
            )
    # ----------------------------------------
    # MITRE ATT&CK Tab
    # ----------------------------------------

    with tab3:

        st.header("🎯 MITRE ATT&CK Mapping")

        mitre_rows = []

        for detection in detections:

            mapping = get_mitre_info(detection["attack"])

            mitre_rows.append({
                "Attack": detection["attack"],
                "Technique ID": mapping["technique"],
                "Technique Name": mapping["name"],
            })

        if mitre_rows:

            mitre_df = pd.DataFrame(mitre_rows)

            st.dataframe(
                mitre_df,
                use_container_width=True,
                hide_index=True,
            )

        else:

            st.info("No MITRE mappings available.")
    # ----------------------------------------
    # Incident Reports Tab
    # ----------------------------------------

    with tab4:

        st.header("📄 Incident Reports")

        if detections:

            full_report = ""

            for detection in detections:

                report = generate_report(detection)

                full_report += report
                full_report += "\n"
                full_report += "=" * 60
                full_report += "\n\n"

                with st.expander(detection["attack"]):

                    st.code(report)

            st.download_button(
                label="📥 Download Incident Report",
                data=full_report,
                file_name="incident_report.txt",
                mime="text/plain",
            )

        else:

            st.info("No incident reports available.")