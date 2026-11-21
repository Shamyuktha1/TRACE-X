
import pandas as pd


def detect_failed_login_bursts(
    login_df,
    threshold=5,
    window_minutes=5
):
    """Detect repeated failed logins within a time window."""

    alerts = []

    df = login_df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    df = df.sort_values("timestamp")

    grouped = df.groupby(["user_id", "source_ip"])

    for (user_id, source_ip), group in grouped:

        failures = group[
            group["event_type"] == "LOGIN_FAILED"
        ]

        failure_times = failures["timestamp"].tolist()

        for current_time in failure_times:

            window_start = current_time - pd.Timedelta(
                minutes=window_minutes
            )

            count = sum(
                window_start <= timestamp <= current_time
                for timestamp in failure_times
            )

            if count == threshold:
                alerts.append({
                    "alert_type": "BRUTE_FORCE_ATTEMPT",
                    "severity": "HIGH",
                    "user_id": user_id,
                    "source_ip": source_ip,
                    "timestamp": current_time,
                    "description": (
                        f"{count} failed login attempts "
                        f"within {window_minutes} minutes"
                    )
                })

    return alerts


def detect_success_after_failures(login_df, threshold=5, window_minutes=5):
    """Detect successful logins following repeated failures."""

    alerts = []

    df = login_df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp")

    grouped = df.groupby(["user_id", "source_ip"])

    for (user_id, source_ip), group in grouped:

        for _, row in group.iterrows():

            if row["event_type"] != "LOGIN_SUCCESS":
                continue

            current_time = row["timestamp"]

            previous_failures = group[
                (group["event_type"] == "LOGIN_FAILED") &
                (group["timestamp"] < current_time) &
                (
                    group["timestamp"] >=
                    current_time - pd.Timedelta(minutes=window_minutes)
                )
            ]

            if len(previous_failures) >= threshold:
                alerts.append({
                    "alert_type": "SUCCESS_AFTER_FAILURES",
                    "severity": "CRITICAL",
                    "user_id": user_id,
                    "source_ip": source_ip,
                    "timestamp": current_time,
                    "description": (
                        f"Successful login after "
                        f"{len(previous_failures)} failed attempts"
                    )
                })

    return alerts


def detect_unfamiliar_ips(login_df, trusted_ips):
    """Identify login activity from IPs outside the trusted baseline."""

    alerts = []

    df = login_df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    unfamiliar = df[
        ~df["source_ip"].isin(trusted_ips)
    ]

    for _, row in unfamiliar.iterrows():

        alerts.append({
            "alert_type": "UNFAMILIAR_IP",
            "severity": "MEDIUM",
            "user_id": row["user_id"],
            "source_ip": row["source_ip"],
            "timestamp": row["timestamp"],
            "description": (
                f"Login activity from unfamiliar IP "
                f"{row['source_ip']}"
            )
        })

    return alerts


def detect_sensitive_file_activity(file_df):
    """Detect access or modification of potentially sensitive files."""

    alerts = []

    sensitive_keywords = [
        "confidential",
        "customer",
        "payroll",
        "secret",
        "database",
        "financial"
    ]

    df = file_df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    for _, row in df.iterrows():

        file_name = str(row["file_name"]).lower()
        action = str(row["action"]).upper()

        is_sensitive = any(
            keyword in file_name
            for keyword in sensitive_keywords
        )

        if is_sensitive and action in [
            "FILE_ACCESS",
            "FILE_MODIFIED"
        ]:

            alerts.append({
                "alert_type": "SENSITIVE_FILE_ACTIVITY",
                "severity": (
                    "HIGH" if action == "FILE_MODIFIED"
                    else "MEDIUM"
                ),
                "user_id": row["user_id"],
                "source_ip": None,
                "timestamp": row["timestamp"],
                "description": (
                    f"{action} detected on {row['file_name']}"
                )
            })

    return alerts


def run_all_detections(login_df, file_df, trusted_ips):
    """Run all detection rules and return combined alerts."""

    alerts = []

    alerts.extend(
        detect_failed_login_bursts(login_df)
    )

    alerts.extend(
        detect_success_after_failures(login_df)
    )

    alerts.extend(
        detect_unfamiliar_ips(login_df, trusted_ips)
    )

    alerts.extend(
        detect_sensitive_file_activity(file_df)
    )

    return alerts
