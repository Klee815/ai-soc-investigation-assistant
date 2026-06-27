from parser import load_logs
from analyzer import (
    detect_brute_force,
    detect_powershell,
    detect_file_access,
)
from report_generator import generate_report


def main():
    print("=" * 50)
    print("AI SOC Investigation Assistant")
    print("=" * 50)

    logs = load_logs("data/sample_logs.csv")

    if logs is None:
        return

    print("\nSecurity Logs:\n")
    print(logs)

    detections = [
        detect_brute_force(logs),
        detect_powershell(logs),
        detect_file_access(logs),
    ]

    print("\nDetected Security Events")
    print("=" * 50)

    found = False

    for result in detections:
        if result:
            found = True
            report = generate_report(result)
            print(report)

    if not found:
        print("No suspicious activity detected.")


if __name__ == "__main__":
    main()