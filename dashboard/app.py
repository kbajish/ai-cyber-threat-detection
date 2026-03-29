import streamlit as st
import requests
import pandas as pd
import json
import time

API_URL = "http://localhost:8000"

st.set_page_config(
    page_title = "AI Cyber Threat Detection",
    page_icon  = "🔐",
    layout     = "wide"
)

st.title("🔐 AI Cyber Threat Detection — Live Dashboard")

# ── Sidebar ───────────────────────────────────────────────────────
with st.sidebar:
    st.header("Controls")
    refresh_rate = st.slider("Auto-refresh (sec)", 1, 10, 3)
    show_benign  = st.toggle("Show BENIGN traffic", value=False)
    st.markdown("---")
    st.markdown("**Start live simulator:**")
    st.code("python -m src.simulation.replay --delay 0.5")
    st.markdown("---")
    if st.button("Check API health"):
        try:
            r = requests.get(f"{API_URL}/health", timeout=3)
            st.success(f"API online — {r.json()}")
        except Exception:
            st.error("API not reachable")

# ── Fetch audit log ───────────────────────────────────────────────
try:
    logs     = requests.get(f"{API_URL}/audit?limit=200", timeout=3).json()
    df_logs  = pd.DataFrame(logs) if logs else pd.DataFrame()
    api_live = True
except Exception:
    df_logs  = pd.DataFrame()
    api_live = False
    st.warning("API not reachable — start the API first.")

# ── Metrics row ───────────────────────────────────────────────────
col1, col2, col3, col4 = st.columns(4)

if not df_logs.empty:
    total    = len(df_logs)
    threats  = (df_logs["prediction"] != "BENIGN").sum()
    avg_conf = df_logs["confidence"].mean()
    top_attack = (
        df_logs[df_logs["prediction"] != "BENIGN"]["prediction"]
        .value_counts().idxmax()
        if threats > 0 else "None"
    )
    col1.metric("Total events",     total)
    col2.metric("Threats detected", int(threats))
    col3.metric("Threat rate",      f"{threats/total*100:.1f}%")
    col4.metric("Top attack",       top_attack)
else:
    col1.metric("Total events",     0)
    col2.metric("Threats detected", 0)
    col3.metric("Threat rate",      "0%")
    col4.metric("Top attack",       "—")

st.markdown("---")

# ── Tabs ──────────────────────────────────────────────────────────
tab1, tab2, tab3 = st.tabs(["Live Feed", "Latest Threat Detail", "Audit Log"])

# ── Tab 1: Live feed ──────────────────────────────────────────────
with tab1:
    st.subheader("Live event feed")

    if not df_logs.empty:
        display = df_logs.copy()
        if not show_benign:
            display = display[display["prediction"] != "BENIGN"]

        display = display.head(50)[[
            "timestamp", "prediction", "confidence",
            "technique_id", "tactic"
        ]].copy()

        def row_color(row):
            if row["prediction"] == "BENIGN":
                return [""] * len(row)
            elif row["confidence"] > 0.9:
                return ["background-color: #fde8e8"] * len(row)
            else:
                return ["background-color: #fff3cd"] * len(row)

        st.dataframe(
            display.style.apply(row_color, axis=1),
            use_container_width = True,
            height              = 400
        )
    else:
        st.info("No events yet. Start the simulator to see live detections.")

# ── Tab 2: Latest threat detail ───────────────────────────────────
with tab2:
    st.subheader("Latest threat detail")

    if not df_logs.empty:
        threats_df = df_logs[df_logs["prediction"] != "BENIGN"]

        if not threats_df.empty:
            latest = threats_df.iloc[0]

            c1, c2 = st.columns([1, 2])

            with c1:
                st.error(f"**{latest['prediction']}**")
                st.metric("Confidence", f"{latest['confidence']:.2%}")

                if latest.get("technique_id"):
                    st.warning(
                        f"MITRE: `{latest['technique_id']}`\n\n"
                        f"Tactic: {latest.get('tactic', '')}"
                    )
                st.caption(f"Detected: {latest['timestamp']}")
                st.caption(f"Source hash: `{latest['ip_hash']}`")

            with c2:
                if latest.get("top_features"):
                    feats = (
                        json.loads(latest["top_features"])
                        if isinstance(latest["top_features"], str)
                        else latest["top_features"]
                    )
                    feat_df = pd.DataFrame(feats).set_index("feature")
                    st.bar_chart(feat_df["shap_value"])
        else:
            st.info("No threats detected yet.")
    else:
        st.info("No events yet.")

# ── Tab 3: Audit log ──────────────────────────────────────────────
with tab3:
    st.subheader("DSGVO audit log")
    st.caption("Source IPs are SHA-256 pseudonymised — raw IPs are never stored.")

    if not df_logs.empty:
        st.dataframe(
            df_logs[[
                "timestamp", "ip_hash", "prediction",
                "confidence", "technique_id", "model_version"
            ]],
            use_container_width = True
        )
    else:
        st.write("No audit records yet.")

# ── Auto-refresh ──────────────────────────────────────────────────
time.sleep(refresh_rate)
st.rerun()