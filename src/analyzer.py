from models import Detection
import pandas as pd


def detect_brute_force(logs):
    failed = logs[logs["event"] == "SSH Login Failed"]
    success = logs[logs["event"] == "SSH Login Success"]

    if failed.empty or success.empty:
        return None

    failed_counts = failed.groupby("ip").size()

    for ip, count in failed_counts.items():
        if count >= 3 and ip in success["ip"].values:
            return {
                "attack": "SSH Brute Force",
                "severity": "High",
                "source_ip": ip,
                "description": f"{count} failed logins followed by a successful login."
            }

    return None


def detect_powershell(logs):
    suspicious = logs[logs["event"] == "PowerShell Execution"]

    if not suspicious.empty:
        row = suspicious.iloc[0]

        return {
            "attack": "PowerShell Execution",
            "severity": "Medium",
            "source_ip": row["ip"],
            "description": "PowerShell execution detected."
        }

    return None


def detect_file_access(logs):
    suspicious = logs[logs["event"] == "File Access"]

    if not suspicious.empty:
        row = suspicious.iloc[0]

        return {
            "attack": "Sensitive File Access",
            "severity": "Low",
            "source_ip": row["ip"],
            "description": "File access activity detected."
        }

    return None