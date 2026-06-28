# 🛡 AI SOC Investigation Assistant

An interactive **Security Operations Center (SOC)** dashboard built with **Python**, **Streamlit**, **Pandas**, and **Plotly**. This application analyzes security logs, detects suspicious activity, maps findings to the **MITRE ATT&CK** framework, and generates incident reports.

---

# 📖 Overview

The **AI SOC Investigation Assistant** simulates a real-world Security Operations Center (SOC) investigation workflow.

Users can upload security logs, detect suspicious behavior, visualize security events, map attacks to MITRE ATT&CK techniques, and generate incident reports through an easy-to-use dashboard.

This project demonstrates practical cybersecurity, Python programming, and data visualization skills commonly used in SOC Analyst and Blue Team roles.

---

# ✨ Features

- 📂 Upload CSV security logs
- 🔍 Search logs by Source IP
- 🚨 Detect SSH brute-force attacks
- ⚡ Detect PowerShell execution
- 📁 Detect suspicious file access
- 📊 Interactive security dashboard
- 🥧 Alert Severity Pie Chart
- 📈 Events by Source IP Chart
- 🎯 MITRE ATT&CK Mapping
- 📄 Generate Incident Reports
- 📥 Download Investigation Reports

---

# 📸 Screenshots

## 🖥 Dashboard

![Dashboard](screenshots/dashboard.png)

---

## 📜 Security Logs

### Security Log Viewer

![Security Logs](screenshots/log.png)

### Search / Filter Example

![Filtered Logs](screenshots/logs2.png)

---

## 🎯 MITRE ATT&CK Mapping

![MITRE ATT&CK](screenshots/mitre.png)

---

## 📄 Incident Reports

![Incident Reports](screenshots/reports.png)

---

# 🚨 Detection Rules

## SSH Brute Force Detection

**Logic**

- Three or more failed SSH login attempts
- Followed by a successful login

**Severity:** High

---

## PowerShell Execution

Detects PowerShell execution activity.

**Severity:** Medium

---

## Sensitive File Access

Detects suspicious file access events.

**Severity:** Low

---

# 📊 Dashboard Overview

The dashboard provides:

- High, Medium, and Low severity alert counts
- Total security events
- Unique Source IP addresses
- Interactive visualizations
- Security log viewer
- MITRE ATT&CK mapping
- Downloadable incident reports

---

# 🎯 MITRE ATT&CK Techniques

| Detection | MITRE Technique |
|------------|-----------------|
| SSH Brute Force | T1110 – Brute Force |
| PowerShell Execution | T1059.001 – PowerShell |
| Sensitive File Access | T1005 – Data from Local System |

---

# 🛠 Technologies

- Python
- Streamlit
- Pandas
- Plotly
- Git
- GitHub

---

# 📂 Project Structure

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
├── screenshots/
│   ├── dashboard.png
│   ├── log.png
│   ├── logs2.png
│   ├── mitre.png
│   └── reports.png
│
└── src/
    ├── analyzer.py
    ├── parser.py
    ├── mitre_mapper.py
    ├── report_generator.py
```

---

# ⚙ Installation

Clone the repository

```bash
git clone https://github.com/Klee815/ai-soc-investigation-assistant.git
```

Go to the project folder

```bash
cd ai-soc-investigation-assistant
```

Install dependencies

```bash
pip install -r requirements.txt
```

Run the application

```bash
streamlit run app.py
```

---

# 💼 Skills Demonstrated

- Python Programming
- Security Log Analysis
- Threat Detection
- MITRE ATT&CK Framework
- Incident Response
- Data Visualization
- Streamlit Development
- Git & GitHub
- Security Reporting

---

# 🚀 Future Improvements

- AI-powered Investigation Summary
- PDF Report Export
- Threat Intelligence Integration
- Timeline Visualization
- Docker Deployment
- Streamlit Cloud Deployment

---

# 👨‍💻 Author

**Kayoung Lee**

Bachelor of Science in Cybersecurity and Information Assurance (WGU)

Aspiring SOC Analyst interested in Threat Detection, Incident Response, SIEM, Blue Team Operations, and Security Automation.

---

# 📄 License

This project is intended for educational and portfolio purposes.