	
import re
from pathlib import Path

import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="OSPF & BGP Route Monitor",
    page_icon="🌐",
    layout="wide",
)

LOG_FILE = Path("route_monitor.log")

st.title("OSPF & BGP Route Monitor")
st.caption("Routing Protocol Analysis & Anomaly Detection")

if not LOG_FILE.exists():
    st.error("route_monitor.log was not found. Run the C analyzer first.")
    st.stop()

log_text = LOG_FILE.read_text(encoding="utf-8", errors="replace")
lines = log_text.splitlines()

# Parse timestamps and event messages from the log.
records = []
for line in lines:
    match = re.match(
        r"^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s*(.*)$",
        line,
    )
    if match:
        records.append({
            "Time": pd.to_datetime(match.group(1), errors="coerce"),
            "Event": match.group(2),
        })

df = pd.DataFrame(records, columns=["Time", "Event"])
if not df.empty:
    df = df.dropna(subset=["Time"])

def contains(pattern):
    if df.empty:
        return pd.Series(dtype=bool)
    return df["Event"].str.contains(pattern, case=False, regex=True, na=False)

# Event counts from log entries, not unique packets.
announcements = int(contains(r"Announced route:").sum())
withdrawals = int(contains(r"Withdrawn route:").sum())
lsa_updates = int(contains(r"OSPF Link-State Update detected:").sum())
lsa_changes = int(contains(r"OSPF LSA sequence changed:").sum())
bgp_notifications = int(contains(r"BGP NOTIFICATION received!").sum())
alerts = int(contains(r"\b(ALERT|WARNING):").sum())

# Reconstruct the current prefix set from announcement/withdrawal events.
tracked = set()
prefix_pattern = r"(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})"

for line in lines:
    announced = re.search(r"Announced route:\s*" + prefix_pattern, line)
    withdrawn = re.search(r"Withdrawn route:\s*" + prefix_pattern, line)

    if announced:
        tracked.add(announced.group(1))
    if withdrawn:
        tracked.discard(withdrawn.group(1))

if st.button("Refresh dashboard"):
    st.rerun()

st.subheader("Monitoring overview")
cols = st.columns(3)
cols[0].metric("Tracked prefixes", len(tracked))
cols[1].metric("Route announcements", announcements)
cols[2].metric("Route withdrawals", withdrawals)

cols = st.columns(3)
cols[0].metric("OSPF LS Updates", lsa_updates)
cols[1].metric("OSPF LSA changes", lsa_changes)
cols[2].metric("Anomaly alerts", alerts)

st.subheader("Event trends")

if not df.empty:
    trend_df = df.copy()
    trend_df["Category"] = "Other"

    trend_df.loc[
        trend_df["Event"].str.contains("OSPF Link-State Update detected:", na=False),
        "Category",
    ] = "OSPF LS Updates"
    trend_df.loc[
        trend_df["Event"].str.contains("OSPF LSA sequence changed:", na=False),
        "Category",
    ] = "OSPF LSA changes"
    trend_df.loc[
        trend_df["Event"].str.contains("Announced route:", na=False),
        "Category",
    ] = "Route announcements"
    trend_df.loc[
        trend_df["Event"].str.contains("Withdrawn route:", na=False),
        "Category",
    ] = "Route withdrawals"
    trend_df.loc[
        trend_df["Event"].str.contains(r"\b(ALERT|WARNING):", case=False, na=False),
        "Category",
    ] = "Alerts"
    trend_df.loc[
        trend_df["Event"].str.contains("BGP NOTIFICATION received!", na=False),
        "Category",
    ] = "BGP notifications"

    selected_categories = st.multiselect(
        "Choose event categories",
        options=sorted(trend_df["Category"].unique()),
        default=sorted(trend_df["Category"].unique()),
    )

    filtered = trend_df[trend_df["Category"].isin(selected_categories)]

    if not filtered.empty:
        chart_data = (
            filtered.assign(Time=filtered["Time"].dt.floor("min"))
            .groupby(["Time", "Category"])
            .size()
            .unstack(fill_value=0)
            .sort_index()
        )
        st.line_chart(chart_data)
    else:
        st.info("No events match the selected categories.")
else:
    st.info("No timestamped events found in the log yet.")

st.subheader("Currently tracked prefixes")
if tracked:
    st.dataframe(
        pd.DataFrame({"Prefix": sorted(tracked)}),
        use_container_width=True,
        hide_index=True,
    )
else:
    st.info("No currently tracked prefixes found in the log.")

st.subheader("Recent events")

if not df.empty:
    search = st.text_input("Search event messages")
    show_alerts_only = st.checkbox("Show only alerts and warnings")
    time_range = st.selectbox(
        "Event history",
        ["All events", "Last 15 minutes", "Last 1 hour", "Last 24 hours"]
    )
    recent = df.copy()
     
    if time_range != "All events":
       minutes = {
            "Last 15 minutes": 15,
            "Last 1 hour": 60,
            "Last 24 hours": 1440,
       }[time_range]

       cutoff = pd.Timestamp.now() - pd.Timedelta(minutes=minutes)
       recent = recent[recent["Time"] >= cutoff]

    if search:
        recent = recent[
            recent["Event"].str.contains(search, case=False, na=False)
        ]
    if show_alerts_only:
        recent = recent[
            recent["Event"].str.contains(
                r"\b(ALERT|WARNING):", case=False, na=False
            )
        ]

    st.dataframe(
        recent.tail(100).sort_values("Time", ascending=False),
        use_container_width=True,
        hide_index=True,
    )
else:
    st.info("No timestamped events to display.")

st.caption(
    "Metrics count matching log entries, including repeated test runs. "
    "Prefix state is reconstructed from log events and may not match the "
    "analyzer's in-memory state. This dashboard analyzes saved logs; "
    "it is not a live packet-capture interface."
)
