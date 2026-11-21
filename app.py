
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import networkx as nx
import hashlib
import hmac


from utils.data_processor import load_all_evidence, validate_evidence
from engines.detection_engine import run_all_detections
from engines.correlation_engine import correlate_evidence
from engines.risk_engine import calculate_risk_score
from engines.hash_engine import (
    calculate_uploaded_file_hash,
    verify_uploaded_file
)
from datetime import datetime
from engines.evidence_db import (
    initialize_database,
    save_evidence_record,
    get_all_evidence,
    record_custody_event,
    get_custody_history
)
def verify_password(password, salt, stored_hash):
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        600000
    ).hex()

    return hmac.compare_digest(password_hash, stored_hash)

# =========================================================
# PAGE CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="TRACE-X | Forensic Intelligence",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)
# Initialize permanent evidence database
initialize_database()
if "evidence_manifest" not in st.session_state:
    st.session_state.evidence_manifest = []
if "custody_logged_events" not in st.session_state:
    st.session_state.custody_logged_events = set()
# Authentication session
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if "investigator_username" not in st.session_state:
    st.session_state.investigator_username = ""
# TRACE-X LOGIN SYSTEM

if not st.session_state.authenticated:

    st.markdown("""
        <div style="text-align:center; padding:40px;">
            <h1 style="color:#E11D48;">🔍 TRACE-X</h1>
            <h3 style="color:#F8EDEF;">FORENSIC INTELLIGENCE SYSTEM</h3>
            <p style="color:#B9A6AD;">Secure Investigator Access</p>
        </div>
    """, unsafe_allow_html=True)

    with st.form("login_form"):

        username = st.text_input("Investigator Username")

        password = st.text_input(
            "Password",
            type="password"
        )

        login_button = st.form_submit_button(
            "🔐 LOGIN",
            use_container_width=True
        )

        if login_button:

            if (
                username == st.secrets["auth"]["username"]
                and verify_password(
                    password,
                    st.secrets["auth"]["salt"],
                    st.secrets["auth"]["password_hash"]
                )
            ):

                st.session_state.authenticated = True
                st.session_state.investigator_username = username

                st.success("Login successful!")
                st.rerun()

            else:
                st.error("Invalid username or password.")

    st.stop()
# INVESTIGATOR SESSION CONTROLS

if st.session_state.authenticated:

    st.sidebar.markdown(
        f"👤 Investigator: **{st.session_state.investigator_username}**"
    )

    if st.sidebar.button("🚪 Logout", use_container_width=True):

        st.session_state.authenticated = False
        st.session_state.investigator_username = ""

        st.rerun()



# =========================================================
# CUSTOM UI DESIGN
# =========================================================

st.markdown("""
<style>

/* MAIN APPLICATION */
.stApp {
    background: #090609;
    color: #F8EDEF;
}

[data-testid="stHeader"] {
    background: rgba(9, 6, 9, 0.96);
}

.block-container {
    padding-top: 2rem;
    padding-bottom: 3rem;
    max-width: 1500px;
}

/* SIDEBAR */
[data-testid="stSidebar"] {
    background: #160A10;
    border-right: 1px solid #54202F;
}

[data-testid="stSidebar"] * {
    color: #F5DDE4;
}

/* TYPOGRAPHY */
h1, h2, h3 {
    color: #FFF0F3 !important;
    letter-spacing: -0.5px;
}

p, label {
    color: #D0B5BE;
}

/* HERO SECTION */
.hero {
    background: linear-gradient(115deg, #260B15, #481020, #210911);
    border: 1px solid #A51D40;
    border-radius: 18px;
    padding: 30px;
    margin-bottom: 25px;
}

.hero-title {
    font-size: 38px;
    font-weight: 800;
    color: #FFFFFF;
    letter-spacing: 1px;
}

.hero-subtitle {
    color: #FF4D6D;
    font-size: 14px;
    font-weight: 600;
    letter-spacing: 2px;
    text-transform: uppercase;
}

.hero-description {
    color: #E5C1CB;
    font-size: 15px;
    margin-top: 12px;
}

/* METRIC CARDS */
.metric-card {
    background: linear-gradient(145deg, #28101A, #160A10);
    border: 1px solid #642438;
    border-radius: 15px;
    padding: 21px;
    min-height: 130px;
}
/* METRIC CARD HOVER EFFECT */
.metric-card {
    transition: transform 0.25s ease, box-shadow 0.25s ease;
}

.metric-card:hover {
    transform: translateY(-4px);
    box-shadow: 0 8px 25px rgba(225, 29, 72, 0.18);
    border-color: #E11D48;
}

/* HERO GLOW */
.hero {
    box-shadow: 0 0 25px rgba(225, 29, 72, 0.08);
}

.metric-label {
    color: #D6A6B5;
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 1px;
}

.metric-value {
    color: #FFFFFF;
    font-size: 32px;
    font-weight: 800;
    margin-top: 12px;
}

.metric-note {
    color: #FF5877;
    font-size: 12px;
    margin-top: 5px;
}

/* SECTION CARDS */
.panel {
    background: #190B12;
    border: 1px solid #512033;
    border-radius: 15px;
    padding: 20px;
    margin-bottom: 15px;
}

/* STATUS LABELS */
.status {
    display: inline-block;
    background: #421321;
    color: #FF8199;
    border: 1px solid #A52B4B;
    border-radius: 20px;
    padding: 7px 14px;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 1px;
}

/* TABS */
.stTabs [data-baseweb="tab-list"] {
    gap: 10px;
    border-bottom: 1px solid #542033;
}

.stTabs [data-baseweb="tab"] {
    background: #190B12;
    border-radius: 8px 8px 0 0;
    color: #D0B5BE;
    padding: 12px 18px;
}

.stTabs [aria-selected="true"] {
    background: #491426 !important;
    color: #FF5877 !important;
}

/* BUTTONS */
.stButton button,
.stDownloadButton button {
    background: #8F1535;
    color: #FFFFFF;
    border: 1px solid #E11D48;
    border-radius: 9px;
}

.stButton button:hover,
.stDownloadButton button:hover {
    background: #B91C45;
    border-color: #FF718B;
    color: white;
}

/* INPUTS */
.stTextInput input,
.stNumberInput input,
.stTextArea textarea {
    background: #1B0C13;
    color: #FFFFFF;
    border: 1px solid #713047;
}

/* DATAFRAMES */
[data-testid="stDataFrame"] {
    border: 1px solid #542033;
    border-radius: 10px;
}

/* DIVIDERS */
hr {
    border-color: #542033;
}

/* ALERTS */
/* ALERTS */
[data-testid="stAlert"] {
    background: #241019 !important;
    border: 1px solid #A52B4B !important;
    color: #F5DDE4 !important;
}

[data-testid="stAlert"] > div {
    background: #241019 !important;
}

[data-testid="stAlert"] p {
    color: #F5DDE4 !important;
}

[data-testid="stAlert"] svg {
    color: #FF5877 !important;
}
}

/* FOOTER */
footer {
    visibility: hidden;
}

</style>
""", unsafe_allow_html=True)


# =========================================================
# SIDEBAR
# =========================================================

st.sidebar.markdown("""
<div style="padding:12px 0 22px 0;">
    <div style="font-size:27px;font-weight:800;color:#FF4D6D;">
        🔍 TRACE-X
    </div>
    <div style="font-size:11px;letter-spacing:2px;color:#FF8199;">
        FORENSIC INTELLIGENCE
    </div>
</div>
""", unsafe_allow_html=True)

st.sidebar.markdown("---")

st.sidebar.markdown("### INVESTIGATION CONTROL")

trusted_ip_input = st.sidebar.text_input(
    "Trusted IP addresses",
    value="192.168.1.10",
    help="Separate multiple IP addresses with commas."
)

trusted_ips = [
    ip.strip()
    for ip in trusted_ip_input.split(",")
    if ip.strip()
]

st.sidebar.markdown("---")

st.sidebar.markdown("### EVIDENCE CONFIGURATION")

st.sidebar.info(
    "Current mode: Sample investigation\n\n"
    "Evidence sources: Login, Network and File Activity"
)

st.sidebar.markdown("---")

st.sidebar.markdown("""
<div style="font-size:12px;color:#8297AE;">
    TRACE-X v1.0<br>
    Digital Forensics Prototype<br><br>
    Investigation workspace
</div>
""", unsafe_allow_html=True)


# =========================================================
# HERO HEADER
# =========================================================

st.markdown("""
<div class="hero">
    <div class="hero-subtitle">
        DIGITAL FORENSICS / INCIDENT ANALYSIS
    </div>
    <div class="hero-title">
        🔍 TRACE-X
    </div>
    <div style="font-size:20px;font-weight:600;color:#DCEBFA;">
        Cross-Source Evidence Correlation
    </div>
    <div class="hero-description">
        Analyse digital evidence. Identify suspicious patterns.
        Reconstruct potential security incidents.
    </div>
</div>
""", unsafe_allow_html=True)


# =========================================================
# LOAD AND PROCESS EVIDENCE
# =========================================================

try:

    login_df, network_df, file_df = load_all_evidence()

    validate_evidence(login_df, network_df, file_df)

    alerts = run_all_detections(
        login_df,
        file_df,
        trusted_ips
    )

    incidents = correlate_evidence(
        login_df,
        network_df,
        file_df
    )
        # Prepare Incident Investigation Summary
    incident_summaries = []

    for incident_number, incident in enumerate(incidents, start=1):

        event_times = [
            pd.to_datetime(event["timestamp"])
            for event in incident["correlated_events"]
        ]

        incident_summaries.append({
        "Incident ID": f"INC-{incident_number:03d}",
        "User ID": incident["user_id"],
        "Source IP": incident["source_ip"],
        "Session ID": incident["session_id"],
        "First Observed": min(event_times),
        "Last Observed": max(event_times),
        "Correlated Events": incident["event_count"],
        "Evidence Sources": ", ".join(
            incident.get("evidence_sources", [])
    )
})
    risk = calculate_risk_score(alerts)

    # Prepare alert data
    alert_df = pd.DataFrame(alerts)

    # Prepare timeline data
    timeline_records = []

    for incident_number, incident in enumerate(incidents, start=1):

        for event in incident["correlated_events"]:

            timeline_records.append({
                "Incident": f"Incident {incident_number}",
                "User": incident["user_id"],
                "Source": event["source"],
                "Timestamp": event["timestamp"],
                "Event": event["event"],
                "Match Strength": event["match_strength"],
                "Reason": event["reason"]
            })

    timeline_df = pd.DataFrame(timeline_records)


    # =====================================================
    # TOP STATUS
    # =====================================================

    status_col1, status_col2 = st.columns([3, 1])

    with status_col1:
        st.caption(
            "INVESTIGATION ID: TRACE-2026-001  |  "
            "DATASET: SYNTHETIC EVIDENCE"
        )

    with status_col2:
        st.markdown(
            '<div style="text-align:right;">'
            '<span class="status">● ANALYSIS COMPLETE</span>'
            '</div>',
            unsafe_allow_html=True
        )

    st.markdown("## Investigation Overview")


    # =====================================================
    # KPI CARDS
    # =====================================================

    k1, k2, k3, k4 = st.columns(4)

    metrics = [
        (k1, "EVIDENCE SOURCES", "03", "Login / Network / Files"),
        (k2, "SECURITY ALERTS", str(len(alerts)), "Detection engine output"),
        (k3, "CORRELATED INCIDENTS", str(len(incidents)), "Reconstructed sessions"),
        (k4, "RISK SCORE", f"{risk['risk_score']}/100", risk["risk_level"] + " PRIORITY")
    ]

    for column, label, value, note in metrics:

        with column:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">{label}</div>
                <div class="metric-value">{value}</div>
                <div class="metric-note">{note}</div>
            </div>
            """, unsafe_allow_html=True)

    st.write("")


    # =====================================================
    # MAIN TABS
    # =====================================================

    overview_tab, alerts_tab, timeline_tab, graph_tab, evidence_tab = st.tabs([
        "◈ OVERVIEW",
        "⚠ SECURITY ALERTS",
        "◷ INCIDENT TIMELINE",
        "⌘ CORRELATION GRAPH",
        "▤ EVIDENCE VAULT"
    ])


    # =====================================================
    # OVERVIEW TAB
    # =====================================================

    with overview_tab:

        st.markdown("### Investigation Intelligence")

        left, right = st.columns([1, 1])

        with left:

            st.markdown("#### Risk Assessment")

            risk_color = (
                "#FF647C" if risk["risk_level"] == "CRITICAL"
                else "#FFB454" if risk["risk_level"] == "HIGH"
                else "#F5D76E" if risk["risk_level"] == "MEDIUM"
                else "#54D6A0"
            )

            gauge = go.Figure(
                go.Indicator(
                    mode="gauge+number",
                    value=risk["risk_score"],
                    number={
                        "suffix": "/100",
                        "font": {"size": 38, "color": "#F1F6FF"}
                    },
                    title={
                        "text": risk["risk_level"] + " PRIORITY",
                        "font": {"size": 16, "color": risk_color}
                    },
                    gauge={
                        "axis": {
                            "range": [0, 100],
                            "tickcolor": "#A9B9CC"
                        },
                        "bar": {"color": risk_color},
                        "bgcolor": "#142239",
                        "bordercolor": "#263C59",
                        "steps": [
                            {"range": [0, 20], "color": "#18352F"},
                            {"range": [20, 40], "color": "#35402D"},
                            {"range": [40, 70], "color": "#4B3828"},
                            {"range": [70, 100], "color": "#482833"}
                        ]
                    }
                )
            )

            gauge.update_layout(
                height=280,
                paper_bgcolor="#101B2C",
                font_color="#E6EDF7",
                margin=dict(l=25, r=25, t=55, b=15)
            )

            st.plotly_chart(gauge, use_container_width=True)

            st.caption(
                "Illustrative investigation-priority score, "
                "not a probability of malicious activity."
            )

        with right:

            st.markdown("#### Risk Contribution")

            if risk["explanations"]:

                risk_df = pd.DataFrame(risk["explanations"])

                fig = px.bar(
                    risk_df,
                    x="points",
                    y="reason",
                    orientation="h",
                    text="points",
                    color="points",
                    color_continuous_scale=["#247B9B", "#55D6E8"]
                )

                fig.update_layout(
                    height=280,
                    paper_bgcolor="#101B2C",
                    plot_bgcolor="#101B2C",
                    font_color="#DCE7F5",
                    xaxis_title="Priority points",
                    yaxis_title="",
                    coloraxis_showscale=False,
                    margin=dict(l=10, r=20, t=20, b=30)
                )

                st.plotly_chart(fig, use_container_width=True)

            else:
                st.info("No risk contributions were recorded.")

        st.markdown("---")

        st.markdown("#### Risk Explanation")

        for item in risk["explanations"]:
            st.markdown(
                f"- **{item['reason']}** — "
                f"+{item['points']} points"
            )

        st.markdown("---")

        st.markdown("#### Investigation Summary")

        summary1, summary2 = st.columns(2)

        with summary1:
            st.write("**Login records:**", len(login_df))
            st.write("**Network records:**", len(network_df))

        with summary2:
            st.write("**File activity records:**", len(file_df))
            st.write("**Correlated events:**", len(timeline_df))


    # =====================================================
    # ALERTS TAB
    # =====================================================

    with alerts_tab:

        st.markdown("### Security Detection Centre")

        st.caption(
            "Suspicious patterns identified by the TRACE-X detection engine."
        )

        if not alert_df.empty:

            alert_col1, alert_col2 = st.columns(2)

            with alert_col1:
                st.metric("Total Alerts", len(alert_df))

            with alert_col2:
                st.metric(
                    "Affected Users",
                    alert_df["user_id"].nunique()
                )

            st.markdown("---")

            st.dataframe(
                alert_df,
                use_container_width=True,
                hide_index=True
            )

            csv_data = alert_df.to_csv(index=False).encode("utf-8")

            st.download_button(
                "⬇ Download Alert Report",
                data=csv_data,
                file_name="TRACE-X_security_alerts.csv",
                mime="text/csv"
            )
                        # Export Incident Investigation Report
            incident_report_df = pd.DataFrame(incident_summaries)

            incident_report_csv = (
                incident_report_df.to_csv(index=False).encode("utf-8")
            )

            st.download_button(
                "⬇ Download Incident Investigation Report",
                data=incident_report_csv,
                file_name="TRACE-X_incident_investigation_report.csv",
                mime="text/csv"
            )

        else:
            st.success("No suspicious activity detected.")


    # =====================================================
    # TIMELINE TAB
    # =====================================================

    with timeline_tab:

        st.markdown("### Chronological Incident Reconstruction")

        st.caption(
            "Events correlated using session identifiers, user identities, "
            "source IP addresses and timestamps."
        )

        if not timeline_df.empty:

            timeline_df["Timestamp"] = pd.to_datetime(
                timeline_df["Timestamp"]
            )

            fig = px.scatter(
                timeline_df,
                x="Timestamp",
                y="Incident",
                color="Source",
                hover_data=[
                    "User",
                    "Event",
                    "Match Strength",
                    "Reason"
                ],
                title="Correlated Evidence Timeline"
            )

            fig.update_traces(marker=dict(size=13))

            fig.update_layout(
                height=440,
                paper_bgcolor="#101B2C",
                plot_bgcolor="#101B2C",
                font_color="#DCE7F5",
                xaxis_title="Event timestamp",
                yaxis_title="",
                legend_title="Evidence source"
            )

            st.plotly_chart(fig, use_container_width=True)

            st.markdown("#### Reconstructed Events")
            # Incident Investigation Summary
            st.subheader("🔎 Incident Investigation Summary")

            incident_summary_df = pd.DataFrame(incident_summaries)

            if not incident_summary_df.empty:
                st.dataframe(
                    incident_summary_df,
                    use_container_width=True,
                    hide_index=True
                )
            else:
                st.info("No correlated incidents available for investigation.")
            


    # =====================================================
    # CORRELATION GRAPH TAB
    # =====================================================

    with graph_tab:

        st.markdown("### Cross-Source Evidence Relationship Map")

        st.caption(
            "Explore relationships between users, sessions, IP addresses "
            "and correlated evidence events."
        )

        graph = nx.Graph()

        for incident_number, incident in enumerate(incidents, start=1):

            user_node = f"USER:{incident['user_id']}"
            ip_node = f"IP:{incident['source_ip']}"
            session_node = f"SESSION:{incident['session_id']}"

            graph.add_node(user_node, category="User")
            graph.add_node(ip_node, category="IP Address")
            graph.add_node(session_node, category="Session")

            graph.add_edge(user_node, session_node)
            graph.add_edge(session_node, ip_node)

            for event_number, event in enumerate(
                incident["correlated_events"]
            ):

                event_node = (
                    f"EVENT:{incident_number}:{event_number}"
                )

                graph.add_node(
                    event_node,
                    category=event["source"],
                    description=event["event"]
                )

                graph.add_edge(session_node, event_node)

        if graph.number_of_nodes() > 0:

            positions = nx.spring_layout(
                graph,
                seed=42,
                k=1.1
            )

            edge_x = []
            edge_y = []

            for source, target in graph.edges():

                x0, y0 = positions[source]
                x1, y1 = positions[target]

                edge_x.extend([x0, x1, None])
                edge_y.extend([y0, y1, None])

            edge_trace = go.Scatter(
                x=edge_x,
                y=edge_y,
                mode="lines",
                line=dict(width=1.5, color="#36516F"),
                hoverinfo="none"
            )

            category_colors = {
                "User": "#58D6E8",
                "IP Address": "#F4B860",
                "Session": "#A78BFA",
                "LOGIN": "#55D6A0",
                "NETWORK": "#5CA8FF",
                "FILE": "#FF8294"
            }

            node_traces = []

            categories = set(
                nx.get_node_attributes(graph, "category").values()
            )

            for category in categories:

                nodes = [
                    node for node, data in graph.nodes(data=True)
                    if data.get("category") == category
                ]

                node_x = [positions[node][0] for node in nodes]
                node_y = [positions[node][1] for node in nodes]

                hover_text = [
                    graph.nodes[node].get("description", node)
                    for node in nodes
                ]

                node_traces.append(
                    go.Scatter(
                        x=node_x,
                        y=node_y,
                        mode="markers+text",
                        text=[node.split(":")[-1] for node in nodes],
                        textposition="bottom center",
                        hovertext=hover_text,
                        hoverinfo="text",
                        name=category,
                        marker=dict(
                            size=17,
                            color=category_colors.get(
                                category, "#A9B9CC"
                            ),
                            line=dict(width=1, color="#E6EDF7")
                        )
                    )
                )

            graph_fig = go.Figure(
                data=[edge_trace] + node_traces
            )

            graph_fig.update_layout(
                height=600,
                paper_bgcolor="#101B2C",
                plot_bgcolor="#101B2C",
                font_color="#DCE7F5",
                showlegend=True,
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=1.02,
                    xanchor="left",
                    x=0
                ),
                margin=dict(l=20, r=20, t=50, b=20),
                xaxis=dict(visible=False),
                yaxis=dict(visible=False)
            )

            st.plotly_chart(
                graph_fig,
                use_container_width=True
            )

            st.caption(
                "Graph connections represent the matching relationships "
                "used by the current correlation engine. They are not "
                "proof of malicious activity."
            )

        else:
            st.info("No relationships available to visualize.")


       # =====================================================
    # EVIDENCE VAULT TAB
    # =====================================================

    with evidence_tab:

        st.markdown("### Digital Evidence Repository")

        upload_tab, login_tab, network_tab, file_tab, custody_tab = st.tabs([
            "⬆ UPLOAD & INTEGRITY",
            "LOGIN LOGS",
            "NETWORK LOGS",
            "FILE ACTIVITY",
            "CHAIN OF CUSTODY"
        ])

        # UPLOAD CENTRE
        with upload_tab:

            st.markdown("#### Evidence Acquisition Centre")

            st.caption(
                "Upload evidence files and calculate their SHA-256 fingerprints."
            )

            uploaded_files = st.file_uploader(
                "Select evidence files",
                accept_multiple_files=True,
                type=["csv", "txt", "log", "pdf", "jpg", "png", "json"]
            )

            integrity_results = []

            
            if uploaded_files:

                st.markdown("#### Evidence Integrity Analysis")

                for index, uploaded_file in enumerate(uploaded_files):

                    current_hash = calculate_uploaded_file_hash(
                        uploaded_file
                    )

                    st.markdown("---")
                    st.write(f"**Evidence:** {uploaded_file.name}")

                    st.code(current_hash, language="text")

                    baseline = st.text_input(
                        "Enter original SHA-256 baseline (optional)",
                        key=f"baseline_{index}"
                    )

                    if baseline.strip():

                        result = verify_uploaded_file(
                            uploaded_file,
                            baseline
                        )

                        status = result["integrity_status"]

                        if status == "MATCH":
                            st.success("INTEGRITY VERIFIED — MATCH")
                        else:
                            st.error("INTEGRITY WARNING — MISMATCH")

                    else:
                        status = "BASELINE NOT PROVIDED"

                        st.warning(
                            "Hash calculated. Original baseline "
                            "not provided, so integrity cannot be verified."
                        )

                    # Generate an evidence reference ID
                    evidence_id = (
                        f"EVD-{index + 1:03d}-"
                        f"{current_hash[:8].upper()}"
                    )

                    # Preserve the original upload timestamp
                    existing = next(
                        (
                            item for item in st.session_state.evidence_manifest
                            if item["Evidence ID"] == evidence_id
                        ),
                        None
                    )

                    upload_time = (
                        existing["Upload Time"]
                        if existing
                        else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    )

                    manifest_record = {
                        "Evidence ID": evidence_id,
                        "Filename": uploaded_file.name,
                        "SHA-256": current_hash,
                        "Upload Time": upload_time,
                        "Evidence Type": uploaded_file.name.split(".")[-1].upper(),
                        "Integrity Status": status
                    }

                    # Add or update the evidence manifest
                    st.session_state.evidence_manifest = [
                        item for item in st.session_state.evidence_manifest
                        if item["Evidence ID"] != evidence_id
                    ]

                    st.session_state.evidence_manifest.append(
                        manifest_record
                    )
                    save_evidence_record(manifest_record)
                    # Record evidence acquisition in the chain of custody
                    acquisition_key = ("ACQUIRED", evidence_id, current_hash)

                    if acquisition_key not in st.session_state.custody_logged_events:

                        record_custody_event(
                            evidence_id=evidence_id,
                            action="EVIDENCE_ACQUIRED",
                            performed_by=st.session_state.investigator_username,
                            details=f"Evidence file uploaded: {uploaded_file.name}",
                            current_hash=current_hash
                        )

                        st.session_state.custody_logged_events.add(acquisition_key)
                                        # Record integrity verification in the chain of custody
                    if baseline.strip():

                        verification_key = (
                            "VERIFIED",
                            evidence_id,
                            status,
                            current_hash,
                            baseline.strip().lower()
                        )

                        if verification_key not in st.session_state.custody_logged_events:

                            record_custody_event(
                                evidence_id=evidence_id,
                                action="INTEGRITY_VERIFICATION",
                               performed_by=st.session_state.investigator_username,
                                details=f"Integrity verification result: {status}",
                                previous_hash=baseline.strip().lower(),
                                current_hash=current_hash
                            )

                            st.session_state.custody_logged_events.add(
                                verification_key
                            )

                    integrity_results.append({
                        "File Name": uploaded_file.name,
                        "SHA-256": current_hash,
                        "Integrity Status": status
                    })

                # Integrity summary
                st.markdown("---")
                st.markdown("#### Integrity Summary")

                results_df = pd.DataFrame(integrity_results)
                match_count = (results_df["Integrity Status"] == "MATCH").sum()
                mismatch_count = (results_df["Integrity Status"] == "MISMATCH").sum()
                unverified_count = (results_df["Integrity Status"] == "BASELINE NOT PROVIDED").sum()
                st.markdown("#### 🔐 Evidence Integrity Summary")

                col1, col2, col3 = st.columns(3)

                with col1:
                    st.metric("MATCH", match_count)

                with col2:
                    st.metric("MISMATCH", mismatch_count)

                with col3:
                     st.metric("UNVERIFIED", unverified_count)
                st.dataframe(
                    results_df,
                    use_container_width=True,
                    hide_index=True
                )

                report = results_df.to_csv(
                    index=False
                ).encode("utf-8")

                st.download_button(
                    "⬇ Download Integrity Report",
                    data=report,
                    file_name="TRACE-X_integrity_report.csv",
                    mime="text/csv"
                )

                # Evidence manifest
                st.markdown("---")
                st.markdown("#### 📁 Evidence Manifest")

                # Retrieve permanent evidence records from SQLite
                stored_evidence = get_all_evidence()

                manifest_df = pd.DataFrame(stored_evidence)
                st.dataframe(
                    manifest_df,
                    use_container_width=True,
                    hide_index=True
                )

                manifest_csv = manifest_df.to_csv(
                    index=False
                ).encode("utf-8")

                st.download_button(
                    "⬇ Export Evidence Manifest",
                    data=manifest_csv,
                    file_name="TRACE-X_evidence_manifest.csv",
                    mime="text/csv"
                )

            else:
                st.info(
                    "No evidence uploaded yet. Select files to begin analysis."
                )

    # LOGIN LOGS
    with login_tab:

        st.metric("Login Records", len(login_df))

        st.dataframe(
            login_df,
            use_container_width=True,
            hide_index=True
        )

    # NETWORK LOGS
    with network_tab:

        st.metric("Network Records", len(network_df))

        st.dataframe(
            network_df,
            use_container_width=True,
            hide_index=True
        )

    # FILE ACTIVITY
    with file_tab:

        st.metric("File Activity Records", len(file_df))

        st.dataframe(
            file_df,
            use_container_width=True,
            hide_index=True
        )
        with custody_tab:
            st.subheader("Chain of Custody")
            evidence_ids = list(dict.fromkeys(item["evidence_id"] for item in get_all_evidence()))
            selected_evidence_id = st.selectbox("Filter by Evidence ID", ["All"] + evidence_ids)
            custody_records = get_custody_history(
                None if selected_evidence_id == "All" else selected_evidence_id
            )
            st.write("Total custody events:", len(custody_records))
            st.dataframe(pd.DataFrame(custody_records), use_container_width=True, hide_index=True)
            custody_df = pd.DataFrame(custody_records)
            custody_csv = custody_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                "⬇ Download Chain of Custody",
                data=custody_csv,
                file_name="TRACE-X_Chain_of_Custody.csv",
                mime="text/csv"
            )
        login_tab, network_tab, file_tab = st.tabs([
            "LOGIN LOGS",
            "NETWORK LOGS",
            "FILE ACTIVITY"
        ])

        with login_tab:
            st.metric("Login Records", len(login_df))
            st.dataframe(
                login_df,
                use_container_width=True,
                hide_index=True
            )

        with network_tab:
            st.metric("Network Records", len(network_df))
            st.dataframe(
                network_df,
                use_container_width=True,
                hide_index=True
            )

        with file_tab:
            st.metric("File Activity Records", len(file_df))
            st.dataframe(
                file_df,
                use_container_width=True,
                hide_index=True
            )


    # =====================================================
    # FOOTER
    # =====================================================

    st.markdown("---")

    st.markdown("""
    <div style="text-align:center;padding:15px;color:#71869E;">
        <b style="color:#66D9EF;">TRACE-X</b>
        &nbsp; | &nbsp; Digital Forensics & Incident Reconstruction
        <br><br>
        Educational prototype using synthetic evidence data.
        <br>
        Version 1.0
    </div>
    """, unsafe_allow_html=True)


except Exception as error:

    st.error("The investigation could not be completed.")
    st.exception(error)