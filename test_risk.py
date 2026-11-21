
import pandas as pd

from engines.detection_engine import run_all_detections
from engines.risk_engine import calculate_risk_score

# Load evidence
login_df = pd.read_csv("data/login_logs.csv")
file_df = pd.read_csv("data/file_activity.csv")

# Trusted IP baseline
trusted_ips = ["192.168.1.10"]

# Detect suspicious activity
alerts = run_all_detections(
    login_df,
    file_df,
    trusted_ips
)

# Calculate investigation priority
result = calculate_risk_score(alerts)

print("\n========== TRACE-X RISK ASSESSMENT ==========")

print("Risk Score:", result["risk_score"], "/ 100")
print("Risk Level:", result["risk_level"])

print("\nWhy was this score assigned?")

for item in result["explanations"]:
    print(
        f"- {item['reason']}: +{item['points']} points"
    )

print("\n=============================================")
