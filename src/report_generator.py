def generate_report(result):
    report = f"""
==============================
Incident Report
==============================

Attack:
{result['attack']}

Severity:
{result['severity']}

Source IP:
{result['source_ip']}

Description:
{result['description']}
"""

    return report