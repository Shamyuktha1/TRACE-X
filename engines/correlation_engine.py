
import pandas as pd


def correlate_evidence(
    login_df,
    network_df,
    file_df,
    window_minutes=10
):
    """Correlate evidence using sessions, identities and timestamps."""

    incidents = []

    login_df = login_df.copy()
    network_df = network_df.copy()
    file_df = file_df.copy()

    # Standardise timestamps
    login_df["timestamp"] = pd.to_datetime(login_df["timestamp"])
    network_df["timestamp"] = pd.to_datetime(network_df["timestamp"])
    file_df["timestamp"] = pd.to_datetime(file_df["timestamp"])

    # Successful logins only
    successful_logins = login_df[
        login_df["event_type"] == "LOGIN_SUCCESS"
    ].sort_values("timestamp")

    # Prevent duplicate incidents for the same session
    anchors = successful_logins.drop_duplicates(
        subset=["session_id"],
        keep="first"
    )

    for _, login in anchors.iterrows():

        anchor_time = login["timestamp"]
        user_id = login["user_id"]
        source_ip = login["source_ip"]
        session_id = login["session_id"]

        window_end = anchor_time + pd.Timedelta(
            minutes=window_minutes
        )

        events = [{
            "source": "LOGIN",
            "timestamp": anchor_time,
            "event": "Successful login",
            "match_strength": "ANCHOR",
            "reason": "Starting point of investigation"
        }]

        # Correlate network activity by source IP and time
        matching_network = network_df[
            (network_df["source_ip"] == source_ip) &
            (network_df["timestamp"] >= anchor_time) &
            (network_df["timestamp"] <= window_end)
        ]

        for _, network in matching_network.iterrows():

            events.append({
                "source": "NETWORK",
                "timestamp": network["timestamp"],
                "event": (
                    f"{network['protocol']} traffic to "
                    f"{network['destination_ip']} "
                    f"on port {network['destination_port']}"
                ),
                "match_strength": "MODERATE",
                "reason": "Matching source IP and time window"
            })

        # Correlate file activity
        for _, file_event in file_df.iterrows():

            file_time = file_event["timestamp"]

            if not (
                anchor_time <= file_time <= window_end
            ):
                continue

            file_session = file_event["session_id"]

            if pd.notna(session_id) and pd.notna(file_session):
                # When both session IDs exist, require an exact match
                if str(session_id) != str(file_session):
                    continue

                strength = "STRONG"
                reason = "Exact session ID match"

            else:
                # Weaker fallback when session data is unavailable
                if file_event["user_id"] != user_id:
                    continue

                strength = "MODERATE"
                reason = "Matching user ID and time window; session unavailable"

            events.append({
                "source": "FILE",
                "timestamp": file_time,
                "event": (
                    f"{file_event['action']} - "
                    f"{file_event['file_name']}"
                ),
                "match_strength": strength,
                "reason": reason
            })

        events.sort(key=lambda event: event["timestamp"])

        incidents.append({
            "user_id": user_id,
            "source_ip": source_ip,
            "session_id": session_id,
            "anchor_time": anchor_time,
            "correlated_events": events,
            "event_count": len(events),
            "evidence_sources": sorted(set(
                event.get("source", "Unknown")
                for event in events
            ))
})
        })

    return incidents
