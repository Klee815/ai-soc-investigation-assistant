# 🛡 AI SOC Investigation Assistant

An interactive Security Operations Center (SOC) dashboard built with **Python**, **Streamlit**, **Pandas**, and **Plotly**. The application analyzes security logs, detects suspicious activity, maps findings to the MITRE ATT&CK framework, and generates downloadable incident reports.

---

## Overview

This project simulates a lightweight SOC investigation workflow. Analysts can upload security logs, identify common attack patterns, visualize security events, and generate investigation reports from a simple web interface.

---

## Features

* 📂 Upload security log files (CSV)
* 🔍 Search logs by source IP address
* 🚨 Detect SSH brute-force attacks
* ⚡ Detect PowerShell execution events
* 📁 Detect suspicious file access
* 📊 Interactive dashboard with security metrics
* 🥧 Alert severity pie chart
* 📈 Events by source IP visualization
* 🎯 MITRE ATT&CK technique mapping
* 📄 Generate incident reports
* 📥 Download investigation reports

---

## Detection Rules

### SSH Brute Force

Detects multiple failed SSH login attempts followed by a successful login.

**Severity:** High

---

### PowerShell Execution

Detects PowerShell execution events that may indicate malicious activity.

**Severity:** Medium

---

### Sensitive File Access

Detects access to monitored files.

**Severity:** Low

---

## Dashboard

The application provides:

* High / Medium / Low alert counts
* Total log events
* Unique source IP addresses
* Interactive charts
* Security log viewer
* MITRE ATT&CK mappings
* Incident reporting

---

## MITRE ATT&CK Techniques

| Detection             | Technique                      |
| --------------------- | ------------------------------ |
| SSH Brute Force       | T1110 – Brute Force            |
| PowerShell Execution  | T1059.001 – PowerShell         |
| Sensitive File Access | T1005 – Data from Local System |

---

## Technologies

* Python
* Streamlit
* Pandas
* Plotly
* Git
* GitHub

---

## Project Structure

```text
ai-soc-investigation-assistant/
│
├── app.py
├── README.md
├── requirements.txt
├── .gitignore
│
├── data/
│   └── sample_logs.csv
│
├── src/
│   ├── analyzer.py
│   ├── parser.py
│   ├── mitre_mapper.py
│   ├── report_generator.py
│   └── models.py
│
└── screenshots/
    ├── dashboard.png
    ├── logs.png
    ├── logs2.png
    ├── mitre.png
    └── reports.png
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/Klee815/ai-soc-investigation-assistant.git
```

Open the project folder:

```bash
cd ai-soc-investigation-assistant
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the application:

```bash
streamlit run app.py
```

---

## Sample Log Events

The included sample dataset demonstrates:

* SSH Login Failed
* SSH Login Success
* PowerShell Execution
* File Access

---

## Future Improvements

* AI-generated investigation summaries
* PDF incident report export
* Threat intelligence enrichment
* Additional detection rules
* Timeline visualization
* Docker deployment
* Streamlit Community Cloud deployment

---

## Skills Demonstrated

* Security Log Analysis
* Threat Detection
* MITRE ATT&CK Mapping
* Python Development
* Streamlit Application Development
* Data Visualization
* Incident Reporting
* Git & GitHub

---

## Author

**Kayoung Lee**

Bachelor of Science in Cybersecurity and Information Assurance (WGU)

Interested in Security Operations (SOC), Incident Response, Threat Detection, and Blue Team cybersecurity.

---

## License

This project is provided for educational and portfolio purposes.
