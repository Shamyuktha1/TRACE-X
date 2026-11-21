
import pandas as pd

from engines.correlation_engine import correlate_evidence

# Load all three evidence sources
login_df = pd.read_csv("data/login_logs.csv")
network_df = pd.read_csv("data/network_logs.csv")
file_df = pd.read_csv("data/file_activity.csv")

# Run cross-source correlation
incidents = correlate_evidence(
    login_df,
    network_df,
    file_df,
    window_minutes=10
)

print("\n========== TRACE-X INCIDENT RECONSTRUCTION ==========")

for number, incident in enumerate(incidents, start=1):

    print(f"\nINCIDENT #{number}")
    print("User:", incident["user_id"])
    print("Source IP:", incident["source_ip"])
    print("Session:", incident["session_id"])
    print("Related events:", incident["event_count"])

    for event in incident["correlated_events"]:

        print("\n  Source:", event["source"])
        print("  Time:", event["timestamp"])
        print("  Event:", event["event"])
        print("  Match:", event["match_strength"])
        print("  Reason:", event["reason"])

print("\n======================================================")
print("Total incidents examined:", len(incidents))
