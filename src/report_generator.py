from .mitre_mapper import get_mitre_info


def generate_report(result):

    mitre = get_mitre_info(result["attack"])

    report = f"""
========================================
Incident Report
========================================

Attack:
{result['attack']}

Severity:
{result['severity']}

Source IP:
{result['source_ip']}

MITRE ATT&CK

Technique:
{mitre['technique']}

Name:
{mitre['name']}

Description:
{result['description']}
"""

    return report