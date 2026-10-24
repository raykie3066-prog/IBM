# 🛡️ CyberShield — Live IoC Dashboard

A beginner-friendly cybersecurity dashboard built with **Python + Streamlit** that pulls live **Indicators of Compromise (IoCs)** from **VirusTotal** and **AlienVault OTX**.

---

## Features

| Feature | Details |
|---|---|
| **Live IoC Lookups** | IP addresses, domain names, and file hashes via VirusTotal API v3 |
| **Threat Pulses** | Recent threat intelligence feeds from AlienVault OTX |
| **Dark Dashboard** | Modern dark-themed UI with metric cards |
| **Interactive Table** | Filter IoCs by type, severity, and source |
| **Charts** | Severity donut, IoC-type bar, and source-vs-severity stacked bar |
| **CSV Export** | Download filtered results with one click |
| **Demo Mode** | Works without API keys using built-in demo data |

---

## Quick Start

### 1 · Install Python dependencies

```bash
pip install -r requirements.txt
```

### 2 · Get free API keys

**VirusTotal** (free tier — 4 requests/min, 500/day):
1. Sign up at https://www.virustotal.com
2. Go to your profile → **API key**
3. Copy the key

**AlienVault OTX** (free, unlimited):
1. Sign up at https://otx.alienvault.com
2. Go to **Settings → API Integration**
3. Copy the OTX key

### 3 · Configure your keys

```bash
# Copy the example file
cp .env.example .env   # Windows: copy .env.example .env

# Open .env in any text editor and paste your keys:
# VT_API_KEY=abc123...
# OTX_API_KEY=xyz789...
```

> **Tip:** You can also paste keys directly in the sidebar inside the app — no restart needed.

### 4 · Run the app

```bash
streamlit run app.py
```

The dashboard opens automatically at **http://localhost:8501**

---

## Using the App

1. **Load Demo Data** — click the button in the sidebar to explore the UI instantly without any keys.
2. **Enter API keys** — paste them into the sidebar fields (or set them in `.env`).
3. **Enter IoCs to look up** — type IP addresses, domains, or file hashes (one per line) in the sidebar text areas.
4. **Click "Fetch IoCs"** — the app queries both APIs and populates the dashboard.
5. **Filter the table** — use the multiselect dropdowns above the table to narrow results.
6. **Download CSV** — click the download button below the table.

---

## Project Structure

```
cybershield/
├── app.py              ← Main Streamlit application (single file)
├── requirements.txt    ← Python dependencies
├── .env.example        ← API key template (copy to .env)
├── .env                ← Your real keys (never commit this!)
└── README.md           ← This file
```

---

## Rate Limits (Free Tiers)

| API | Limit |
|---|---|
| VirusTotal | 4 requests / minute · 500 requests / day |
| AlienVault OTX | No hard limit on subscribed pulses |

The app adds a small delay between VirusTotal requests to stay within the free-tier rate limit automatically.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` |
| API key error / 401 | Double-check the key in `.env` or the sidebar |
| VirusTotal 429 Too Many Requests | Wait 60 seconds (free-tier rate limit hit) |
| No OTX data | Ensure you are subscribed to at least one pulse at otx.alienvault.com |

---

## Disclaimer

This tool is for **educational purposes** only. Always comply with the terms of service of VirusTotal and AlienVault OTX when using their APIs.
