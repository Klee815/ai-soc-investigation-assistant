import pandas as pd


def load_logs(file_path):
    """
    Load security logs from a CSV file.
    """
    try:
        logs = pd.read_csv(file_path)
        return logs

    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return None

    except Exception as e:
        print(f"Error reading log file: {e}")
        return None