from dataclasses import dataclass


@dataclass
class Detection:
    attack: str
    severity: str
    source_ip: str
    description: str