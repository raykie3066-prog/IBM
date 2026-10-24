"""
CyberShield — Live IoC Dashboard
Pulls Indicators of Compromise from VirusTotal & AlienVault OTX
and displays them in a modern dark-themed Streamlit dashboard.

Setup
-----
1. pip install -r requirements.txt
2. Copy .env.example to .env and fill in your API keys
3. streamlit run app.py
"""

from __future__ import annotations

import os
import time
import datetime
import requests
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from dotenv import load_dotenv

# ── Load environment variables ────────────────────────────────────────────────
load_dotenv()
VT_API_KEY  = os.getenv("VT_API_KEY", "")   # VirusTotal v3 API key
OTX_API_KEY = os.getenv("OTX_API_KEY", "")  # AlienVault OTX API key

# ── Page config (must be first Streamlit call) ────────────────────────────────
st.set_page_config(
    page_title="CyberShield – IoC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS — dark theme ───────────────────────────────────────────────────
st.markdown(
    """
    <style>
    /* ── Base ── */
    html, body, [data-testid="stAppViewContainer"] {
        background-color: #0d1117;
        color: #e6edf3;
        font-family: 'Segoe UI', system-ui, sans-serif;
    }
    [data-testid="stSidebar"] {
        background-color: #161b22;
        border-right: 1px solid #30363d;
    }
    /* ── Metric cards ── */
    .metric-card {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 10px;
        padding: 20px 24px;
        text-align: center;
    }
    .metric-card h3 { font-size: 13px; color: #8b949e; margin: 0 0 6px 0; }
    .metric-card .value { font-size: 36px; font-weight: 700; color: #e6edf3; }
    .metric-card .delta { font-size: 12px; margin-top: 4px; }
    .delta-high  { color: #f85149; }
    .delta-med   { color: #d29922; }
    .delta-good  { color: #3fb950; }
    /* ── Section headings ── */
    .section-header {
        font-size: 16px; font-weight: 600;
        color: #58a6ff; border-bottom: 1px solid #21262d;
        padding-bottom: 6px; margin: 24px 0 12px 0;
    }
    /* ── Pill badges ── */
    .badge { display:inline-block; border-radius:4px; padding:2px 8px; font-size:11px; font-weight:600; }
    .badge-high   { background:#3d1111; color:#f85149; border:1px solid #f85149; }
    .badge-medium { background:#2d1d0a; color:#d29922; border:1px solid #d29922; }
    .badge-low    { background:#0d2518; color:#3fb950; border:1px solid #3fb950; }
    .badge-info   { background:#0d2137; color:#58a6ff; border:1px solid #58a6ff; }
    /* ── Streamlit overrides ── */
    .stDataFrame { border: 1px solid #30363d; border-radius: 8px; }
    div[data-testid="stMetric"] { background:#161b22; border:1px solid #30363d; border-radius:10px; padding:16px; }
    div[data-testid="stMetricValue"] { color:#e6edf3; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ════════════════════════════════════════════════════════════════════════════════
# API HELPERS
# ════════════════════════════════════════════════════════════════════════════════

VT_BASE = "https://www.virustotal.com/api/v3"
OTX_BASE = "https://otx.alienvault.com/api/v1"

def _vt_headers() -> dict:
    return {"x-apikey": VT_API_KEY, "Accept": "application/json"}

def vt_lookup_ip(ip: str) -> dict | None:
    """Look up a single IP on VirusTotal. Returns parsed dict or None on error."""
    if not VT_API_KEY:
        return None
    try:
        r = requests.get(f"{VT_BASE}/ip_addresses/{ip}", headers=_vt_headers(), timeout=10)
        r.raise_for_status()
        data = r.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "ioc": ip,
            "type": "IP",
            "source": "VirusTotal",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "country": data.get("country", "N/A"),
            "threat_label": data.get("popular_threat_classification", {})
                                  .get("suggested_threat_label", "N/A"),
            "fetched_at": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        }
    except requests.RequestException as e:
        st.warning(f"VirusTotal IP lookup failed for {ip}: {e}")
        return None

def vt_lookup_domain(domain: str) -> dict | None:
    """Look up a domain on VirusTotal."""
    if not VT_API_KEY:
        return None
    try:
        r = requests.get(f"{VT_BASE}/domains/{domain}", headers=_vt_headers(), timeout=10)
        r.raise_for_status()
        data = r.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "ioc": domain,
            "type": "Domain",
            "source": "VirusTotal",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "country": data.get("registrar", "N/A"),
            "threat_label": data.get("popular_threat_classification", {})
                                  .get("suggested_threat_label", "N/A"),
            "fetched_at": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        }
    except requests.RequestException as e:
        st.warning(f"VirusTotal domain lookup failed for {domain}: {e}")
        return None

def vt_lookup_hash(file_hash: str) -> dict | None:
    """Look up a file hash (MD5/SHA-1/SHA-256) on VirusTotal."""
    if not VT_API_KEY:
        return None
    try:
        r = requests.get(f"{VT_BASE}/files/{file_hash}", headers=_vt_headers(), timeout=10)
        r.raise_for_status()
        data = r.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "ioc": file_hash,
            "type": "Hash",
            "source": "VirusTotal",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "country": "N/A",
            "threat_label": data.get("popular_threat_classification", {})
                                  .get("suggested_threat_label", "N/A"),
            "fetched_at": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        }
    except requests.RequestException as e:
        st.warning(f"VirusTotal hash lookup failed for {file_hash}: {e}")
        return None

def otx_get_pulses(limit: int = 10) -> list[dict]:
    """Fetch recent AlienVault OTX threat pulses."""
    if not OTX_API_KEY:
        return []
    try:
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        r = requests.get(
            f"{OTX_BASE}/pulses/subscribed",
            headers=headers,
            params={"limit": limit, "page": 1},
            timeout=15,
        )
        r.raise_for_status()
        pulses = r.json().get("results", [])
        rows = []
        for pulse in pulses:
            for ioc in pulse.get("indicators", [])[:5]:  # cap per pulse
                rows.append({
                    "ioc": ioc.get("indicator", "N/A"),
                    "type": ioc.get("type", "N/A").replace("_", " ").title(),
                    "source": "AlienVault OTX",
                    "malicious": 1,        # OTX indicators are pre-vetted threats
                    "suspicious": 0,
                    "harmless": 0,
                    "country": ioc.get("country_code", "N/A") or "N/A",
                    "threat_label": pulse.get("name", "N/A"),
                    "fetched_at": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
                })
        return rows
    except requests.RequestException as e:
        st.warning(f"AlienVault OTX request failed: {e}")
        return []

def count_otx_pulses() -> int:
    """Return the count of subscribed OTX pulses (for the metric card)."""
    if not OTX_API_KEY:
        return 0
    try:
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        r = requests.get(
            f"{OTX_BASE}/pulses/subscribed",
            headers=headers,
            params={"limit": 1},
            timeout=10,
        )
        r.raise_for_status()
        return r.json().get("count", 0)
    except requests.RequestException:
        return 0

# ════════════════════════════════════════════════════════════════════════════════
# DEMO DATA (shown when no API keys are configured)
# ════════════════════════════════════════════════════════════════════════════════

DEMO_IOCS = [
    {"ioc": "185.220.101.45",  "type": "IP",     "source": "VirusTotal",    "malicious": 47, "suspicious": 3, "harmless": 1, "country": "DE", "threat_label": "malware.botnet",     "fetched_at": "2025-01-15 10:00 UTC"},
    {"ioc": "192.168.1.100",   "type": "IP",     "source": "VirusTotal",    "malicious": 0,  "suspicious": 1, "harmless": 68,"country": "US", "threat_label": "N/A",                "fetched_at": "2025-01-15 10:01 UTC"},
    {"ioc": "malware-host.ru", "type": "Domain", "source": "VirusTotal",    "malicious": 32, "suspicious": 5, "harmless": 2, "country": "RU", "threat_label": "phishing.kit",       "fetched_at": "2025-01-15 10:02 UTC"},
    {"ioc": "update-cdn.com",  "type": "Domain", "source": "VirusTotal",    "malicious": 8,  "suspicious": 12,"harmless": 15,"country": "US", "threat_label": "trojan.downloader",  "fetched_at": "2025-01-15 10:03 UTC"},
    {"ioc": "a1b2c3d4e5f6" + "0"*20, "type": "Hash","source": "VirusTotal","malicious": 60, "suspicious": 2, "harmless": 0, "country": "N/A","threat_label": "ransomware",         "fetched_at": "2025-01-15 10:04 UTC"},
    {"ioc": "91.108.4.0",      "type": "IP",     "source": "AlienVault OTX","malicious": 1,  "suspicious": 0, "harmless": 0, "country": "NL", "threat_label": "Telegram C2 Node",   "fetched_at": "2025-01-15 10:05 UTC"},
    {"ioc": "spyware-track.net","type":"Domain", "source": "AlienVault OTX","malicious": 1,  "suspicious": 0, "harmless": 0, "country": "CN", "threat_label": "APT Spy Campaign",   "fetched_at": "2025-01-15 10:06 UTC"},
    {"ioc": "dead" + "b"*28,   "type": "Hash",  "source": "AlienVault OTX","malicious": 1,  "suspicious": 0, "harmless": 0, "country": "N/A","threat_label": "Emotet Payload",     "fetched_at": "2025-01-15 10:07 UTC"},
    {"ioc": "45.33.32.156",    "type": "IP",     "source": "VirusTotal",    "malicious": 2,  "suspicious": 7, "harmless": 45,"country": "US", "threat_label": "N/A",                "fetched_at": "2025-01-15 10:08 UTC"},
    {"ioc": "cdn-static.xyz",  "type": "Domain", "source": "AlienVault OTX","malicious": 1,  "suspicious": 0, "harmless": 0, "country": "UA", "threat_label": "DarkComet RAT",      "fetched_at": "2025-01-15 10:09 UTC"},
]

# ════════════════════════════════════════════════════════════════════════════════
# SESSION STATE — cache fetched IoCs so we don't hit APIs on every widget change
# ════════════════════════════════════════════════════════════════════════════════

if "ioc_data" not in st.session_state:
    st.session_state["ioc_data"] = []
if "last_fetched" not in st.session_state:
    st.session_state["last_fetched"] = None

# ════════════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ════════════════════════════════════════════════════════════════════════════════

with st.sidebar:
    st.markdown("## 🛡️ CyberShield")
    st.markdown("---")

    st.markdown("### 🔑 API Keys")
    vt_key_input  = st.text_input("VirusTotal API Key",  value=VT_API_KEY,  type="password", placeholder="Paste your VT key")
    otx_key_input = st.text_input("AlienVault OTX Key",  value=OTX_API_KEY, type="password", placeholder="Paste your OTX key")
    if vt_key_input:
        VT_API_KEY = vt_key_input
    if otx_key_input:
        OTX_API_KEY = otx_key_input

    st.markdown("---")
    st.markdown("### 🎯 IoCs to Look Up")
    default_ips     = "185.220.101.45\n91.108.4.0"
    default_domains = "malware-host.ru\nspyware-track.net"
    default_hashes  = ""

    ip_input     = st.text_area("IP Addresses (one per line)", value=default_ips,     height=90)
    domain_input = st.text_area("Domains (one per line)",      value=default_domains, height=90)
    hash_input   = st.text_area("File Hashes (one per line)",  value=default_hashes,  height=70)
    otx_limit    = st.slider("OTX Pulses to Fetch", min_value=1, max_value=20, value=5)

    fetch_btn = st.button("🔍 Fetch IoCs", use_container_width=True, type="primary")
    demo_btn  = st.button("🎮 Load Demo Data", use_container_width=True)

    st.markdown("---")
    st.caption("Data refreshes only when you click **Fetch IoCs**.")

# ════════════════════════════════════════════════════════════════════════════════
# DATA FETCHING
# ════════════════════════════════════════════════════════════════════════════════

if demo_btn:
    st.session_state["ioc_data"]    = DEMO_IOCS
    st.session_state["last_fetched"] = "Demo data"

if fetch_btn:
    if not VT_API_KEY and not OTX_API_KEY:
        st.error("⚠️  No API keys configured. Enter at least one key in the sidebar or click **Load Demo Data**.")
    else:
        results = []
        ips     = [x.strip() for x in ip_input.splitlines()     if x.strip()]
        domains = [x.strip() for x in domain_input.splitlines() if x.strip()]
        hashes  = [x.strip() for x in hash_input.splitlines()   if x.strip()]

        with st.spinner("Fetching IoCs from VirusTotal…"):
            for ip in ips:
                row = vt_lookup_ip(ip)
                if row:
                    results.append(row)
                time.sleep(0.2)  # stay within free-tier rate limit (4 req/min)
            for d in domains:
                row = vt_lookup_domain(d)
                if row:
                    results.append(row)
                time.sleep(0.2)
            for h in hashes:
                row = vt_lookup_hash(h)
                if row:
                    results.append(row)
                time.sleep(0.2)

        with st.spinner("Fetching threat pulses from AlienVault OTX…"):
            otx_rows = otx_get_pulses(limit=otx_limit)
            results.extend(otx_rows)

        st.session_state["ioc_data"]    = results
        st.session_state["last_fetched"] = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        if results:
            st.success(f"✅ Fetched {len(results)} IoC records.")
        else:
            st.warning("No results returned. Check your API keys and inputs.")

# ════════════════════════════════════════════════════════════════════════════════
# MAIN DASHBOARD
# ════════════════════════════════════════════════════════════════════════════════

st.markdown(
    "<h1 style='color:#58a6ff;margin-bottom:4px;'>🛡️ CyberShield</h1>"
    "<p style='color:#8b949e;margin-top:0;'>Live Indicators of Compromise Dashboard</p>",
    unsafe_allow_html=True,
)

ioc_data: list[dict] = st.session_state["ioc_data"]
df = pd.DataFrame(ioc_data) if ioc_data else pd.DataFrame(
    columns=["ioc","type","source","malicious","suspicious","harmless","country","threat_label","fetched_at"]
)

# ── Helper: severity label ─────────────────────────────────────────────────────
def severity(row) -> str:
    m = row.get("malicious", 0) if isinstance(row, dict) else row["malicious"]
    if m >= 20:  return "High"
    if m >= 5:   return "Medium"
    if m >= 1:   return "Low"
    return "Clean"

if not df.empty:
    df["severity"] = df.apply(severity, axis=1)

# ── Metrics ────────────────────────────────────────────────────────────────────
total_iocs = len(df)
high_alerts = len(df[df["severity"] == "High"]) if not df.empty else 0
vt_detections = int(df["malicious"].sum()) if not df.empty else 0
otx_pulse_count = count_otx_pulses() if OTX_API_KEY else (
    len(df[df["source"] == "AlienVault OTX"]) if not df.empty else 0
)

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.markdown(f"""<div class="metric-card">
        <h3>Total IoCs Fetched</h3>
        <div class="value">{total_iocs}</div>
        <div class="delta delta-info" style="color:#58a6ff;">IPs · Domains · Hashes</div>
    </div>""", unsafe_allow_html=True)
with col2:
    st.markdown(f"""<div class="metric-card">
        <h3>High Threat Alerts</h3>
        <div class="value" style="color:#f85149;">{high_alerts}</div>
        <div class="delta delta-high">≥ 20 engines flagged</div>
    </div>""", unsafe_allow_html=True)
with col3:
    st.markdown(f"""<div class="metric-card">
        <h3>VirusTotal Detections</h3>
        <div class="value" style="color:#d29922;">{vt_detections}</div>
        <div class="delta delta-med">Total malicious votes</div>
    </div>""", unsafe_allow_html=True)
with col4:
    st.markdown(f"""<div class="metric-card">
        <h3>AlienVault Pulses</h3>
        <div class="value" style="color:#3fb950;">{otx_pulse_count}</div>
        <div class="delta delta-good">Active threat pulses</div>
    </div>""", unsafe_allow_html=True)

st.markdown("<br/>", unsafe_allow_html=True)

# ════════════════════════════════════════════════════════════════════════════════
# CHARTS
# ════════════════════════════════════════════════════════════════════════════════

if not df.empty:
    st.markdown("<div class='section-header'>📊 Threat Visualizations</div>", unsafe_allow_html=True)
    ch1, ch2, ch3 = st.columns(3)

    # ── Chart 1: Severity breakdown (donut) ───────────────────────────────────
    with ch1:
        sev_counts = df["severity"].value_counts().reset_index()
        sev_counts.columns = ["Severity", "Count"]
        color_map = {"High": "#f85149", "Medium": "#d29922", "Low": "#3fb950", "Clean": "#8b949e"}
        fig1 = px.pie(
            sev_counts, names="Severity", values="Count",
            title="Severity Breakdown",
            color="Severity", color_discrete_map=color_map,
            hole=0.5,
        )
        fig1.update_layout(
            paper_bgcolor="#161b22", plot_bgcolor="#161b22",
            font_color="#e6edf3", title_font_color="#58a6ff",
            legend=dict(bgcolor="#161b22"),
            margin=dict(t=40, b=10, l=10, r=10),
        )
        st.plotly_chart(fig1, use_container_width=True)

    # ── Chart 2: IoC type distribution (bar) ─────────────────────────────────
    with ch2:
        type_counts = df["type"].value_counts().reset_index()
        type_counts.columns = ["Type", "Count"]
        fig2 = px.bar(
            type_counts, x="Type", y="Count",
            title="IoC Types", color="Count",
            color_continuous_scale=[[0,"#1f3b5a"],[1,"#58a6ff"]],
        )
        fig2.update_layout(
            paper_bgcolor="#161b22", plot_bgcolor="#161b22",
            font_color="#e6edf3", title_font_color="#58a6ff",
            xaxis=dict(gridcolor="#21262d"), yaxis=dict(gridcolor="#21262d"),
            coloraxis_showscale=False,
            margin=dict(t=40, b=10, l=10, r=10),
        )
        st.plotly_chart(fig2, use_container_width=True)

    # ── Chart 3: Source comparison (bar) ─────────────────────────────────────
    with ch3:
        src_sev = df.groupby(["source","severity"]).size().reset_index(name="Count")
        fig3 = px.bar(
            src_sev, x="source", y="Count", color="severity",
            title="Source vs Severity",
            color_discrete_map=color_map, barmode="stack",
        )
        fig3.update_layout(
            paper_bgcolor="#161b22", plot_bgcolor="#161b22",
            font_color="#e6edf3", title_font_color="#58a6ff",
            xaxis=dict(gridcolor="#21262d"), yaxis=dict(gridcolor="#21262d"),
            legend=dict(bgcolor="#161b22"),
            margin=dict(t=40, b=10, l=10, r=10),
        )
        st.plotly_chart(fig3, use_container_width=True)

# ════════════════════════════════════════════════════════════════════════════════
# IoC TABLE WITH FILTERS
# ════════════════════════════════════════════════════════════════════════════════

st.markdown("<div class='section-header'>📋 IoC Records</div>", unsafe_allow_html=True)

if df.empty:
    st.info("No IoC data loaded yet. Use the sidebar to fetch live data or load the demo dataset.")
else:
    # ── Filter row ─────────────────────────────────────────────────────────────
    f1, f2, f3 = st.columns([2, 2, 2])
    with f1:
        type_filter = st.multiselect(
            "Filter by Type",
            options=sorted(df["type"].unique()),
            default=sorted(df["type"].unique()),
        )
    with f2:
        sev_filter = st.multiselect(
            "Filter by Severity",
            options=["High","Medium","Low","Clean"],
            default=["High","Medium","Low","Clean"],
        )
    with f3:
        src_filter = st.multiselect(
            "Filter by Source",
            options=sorted(df["source"].unique()),
            default=sorted(df["source"].unique()),
        )

    filtered = df[
        df["type"].isin(type_filter) &
        df["severity"].isin(sev_filter) &
        df["source"].isin(src_filter)
    ].copy()

    # ── Colour-coded severity column ───────────────────────────────────────────
    def badge_html(sev: str) -> str:
        cls = {"High":"badge-high","Medium":"badge-medium","Low":"badge-low","Clean":"badge-info"}.get(sev,"badge-info")
        return f'<span class="badge {cls}">{sev}</span>'

    st.caption(f"Showing {len(filtered)} of {len(df)} records")

    display_cols = ["ioc","type","severity","malicious","suspicious","harmless","country","threat_label","source","fetched_at"]
    display_df = filtered[display_cols].rename(columns={
        "ioc": "Indicator", "type": "Type", "severity": "Severity",
        "malicious": "Malicious", "suspicious": "Suspicious", "harmless": "Harmless",
        "country": "Country", "threat_label": "Threat Label",
        "source": "Source", "fetched_at": "Fetched At",
    })

    st.dataframe(
        display_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Malicious":  st.column_config.NumberColumn(format="%d 🔴"),
            "Suspicious": st.column_config.NumberColumn(format="%d 🟡"),
            "Harmless":   st.column_config.NumberColumn(format="%d 🟢"),
            "Severity": st.column_config.TextColumn(),
        },
    )

    # ── CSV download ───────────────────────────────────────────────────────────
    csv = display_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="⬇️ Download as CSV",
        data=csv,
        file_name=f"cybershield_iocs_{datetime.date.today()}.csv",
        mime="text/csv",
    )

# ── Footer ─────────────────────────────────────────────────────────────────────
if st.session_state["last_fetched"]:
    st.caption(f"Last fetched: {st.session_state['last_fetched']}")
st.markdown(
    "<hr style='border-color:#21262d;'/>"
    "<p style='text-align:center;color:#8b949e;font-size:12px;'>CyberShield &nbsp;|&nbsp; "
    "Data from VirusTotal &amp; AlienVault OTX &nbsp;|&nbsp; For educational use</p>",
    unsafe_allow_html=True,
)
