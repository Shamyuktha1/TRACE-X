
import pandas as pd

from engines.detection_engine import run_all_detections

# Load our synthetic forensic datasets
login_df = pd.read_csv("data/login_logs.csv")
file_df = pd.read_csv("data/file_activity.csv")

# Define trusted IP addresses for this fictional investigation
trusted_ips = [
    "192.168.1.10"
]

# Run all detection rules
alerts = run_all_detections(
    login_df,
    file_df,
    trusted_ips
)

# Display investigation results
print("\n========== TRACE-X DETECTION REPORT ==========")

for number, alert in enumerate(alerts, start=1):

    print(f"\nAlert #{number}")
    print("Type:", alert["alert_type"])
    print("Severity:", alert["severity"])
    print("User:", alert["user_id"])
    print("IP:", alert["source_ip"])
    print("Time:", alert["timestamp"])
    print("Reason:", alert["description"])

print("\n==============================================")
print("Total alerts detected:", len(alerts))
