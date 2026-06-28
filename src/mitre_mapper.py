MITRE_MAPPING = {
    "SSH Brute Force": {
        "technique": "T1110",
        "name": "Brute Force"
    },
    "PowerShell Execution": {
        "technique": "T1059.001",
        "name": "PowerShell"
    },
    "Sensitive File Access": {
        "technique": "T1005",
        "name": "Data from Local System"
    }
}


def get_mitre_info(attack):
    return MITRE_MAPPING.get(
        attack,
        {
            "technique": "Unknown",
            "name": "Unknown"
        }
    )