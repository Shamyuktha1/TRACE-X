
import pandas as pd
from pathlib import Path


def load_csv(file_path):
    """Load a CSV evidence file safely."""

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Evidence file not found: {path}")

    if path.suffix.lower() != ".csv":
        raise ValueError("Only CSV files are supported.")

    return pd.read_csv(path)


def load_all_evidence():
    """Load all three TRACE-X evidence sources."""

    login_df = load_csv("data/login_logs.csv")
    network_df = load_csv("data/network_logs.csv")
    file_df = load_csv("data/file_activity.csv")

    return login_df, network_df, file_df


def validate_evidence(login_df, network_df, file_df):
    """Check required columns in each evidence source."""

    required_columns = {
        "login": [
            "timestamp", "user_id", "source_ip",
            "event_type", "session_id"
        ],
        "network": [
            "timestamp", "source_ip", "destination_ip",
            "protocol", "destination_port", "bytes_transferred"
        ],
        "file": [
            "timestamp", "user_id", "file_name",
            "action", "session_id"
        ]
    }

    datasets = {
        "login": login_df,
        "network": network_df,
        "file": file_df
    }

    for name, dataframe in datasets.items():
        missing = set(required_columns[name]) - set(dataframe.columns)

        if missing:
            raise ValueError(
                f"{name} logs are missing columns: {sorted(missing)}"
            )

    return True
