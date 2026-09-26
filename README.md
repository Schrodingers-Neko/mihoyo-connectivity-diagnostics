# miHoYo China Connectivity Diagnostic Suite

A continuous, lightweight network diagnostic tool and decision engine designed for players connecting to miHoYo / HoYoverse China game servers (*Genshin Impact*, *Honkai: Star Rail*, *Zenless Zone Zero*, *Honkai Impact 3rd*) from outside mainland China.

The suite measures multi-zone latency, jitter, packet loss, and TCP handshake times, isolates local and transit network faults, correlates degradations with China peak hours, and automatically determines whether purchasing a game accelerator subscription (e.g., NetEase UU, Leigod) is technically justified.

---

## Architecture Overview

```
F:\projects\personal\mihoyo_connectivity_diagnostics\
├── config.json            # Target definitions, sample intervals, and anomaly thresholds
├── game_discovery.py      # Dynamic scanner for games in miHoYo Launcher directory
├── find_game_ip.py        # CLI inspector for active game server connections
├── monitor.py             # Continuous asynchronous diagnostic daemon
├── analyze.py             # Decision engine & HTML/terminal report generator
├── logs\
│   └── connectivity.csv   # Structured time-series metric logs
├── traces\                # Automated rate-limited traceroute snapshots
└── reports\
    └── summary.html       # Visual dashboard report
```

### Probing Zones (Differential Diagnostics)
To determine *who* is responsible for packet loss and latency spikes, the monitor tests three concurrent zones:
1. **Zone 1: Local Control** (`Local-Gateway` & Cloudflare `1.1.1.1`): Proves if packet loss is caused by your home Wi-Fi, router, or local ISP.
2. **Zone 2: Pacific / Asia Transit Control** (`20.210.150.1` Tokyo East): Proves if trans-oceanic fiber cables are degraded.
3. **Zone 3: miHoYo China Endpoints** (Aliyun Anti-DDoS nodes `203.107.36.87`, `203.107.60.77`, Kunlun CDN `122.156.129.54`, and live game sockets).

---

## Quick Start

### 1. Environment Setup
The project uses Python 3.13 and `uv` (both already configured):

```powershell
# Activate the virtual environment
.venv\Scripts\activate
```

*(Note: All core scripts use Python standard library and have zero mandatory external dependencies. You can also run directly with `python`.)*

### 2. Verify with a Single Test Run
Run one complete diagnostic cycle across all targets:

```powershell
python monitor.py --test-once
```

### 3. Inspect Live Game Connections
Launch *Genshin Impact*, *Honkai: Star Rail*, or *Zenless Zone Zero*, then run:

```powershell
python find_game_ip.py
```

This dynamically scans `D:\Program Files\miHoYo Launcher\games`, inspects the running game process, and shows active connected server IPs, ports, and protocols (e.g. UDP KCP game tick vs TCP dispatch).

To continuously watch active game connections:
```powershell
python find_game_ip.py --watch
```

To automatically append discovered game server IPs into `config.json`:
```powershell
python find_game_ip.py --add-to-config
```

### 4. Start Continuous Monitoring
Start the continuous monitoring probe (logs every 20 seconds to `logs\connectivity.csv`):

```powershell
python monitor.py
```

#### Run Silently in the Background:
In PowerShell, launch as a detached background process:
```powershell
Start-Process -FilePath "python.exe" -ArgumentList "monitor.py --quiet" -WindowStyle Hidden
```

To stop a background monitor:
```powershell
Stop-Process -Name "python"
```

### 5. Generate Buying Decision Report
At any time (after collecting samples across a gaming session or peak hours), run:

```powershell
python analyze.py --html
```

This evaluates the telemetry data against the **Go / No-Go Decision Matrix**, prints a plain-English verdict, and generates a formatted HTML dashboard at `reports\summary.html`.

---

## The Decision Matrix

| Observed Telemetry Pattern | Root Cause | Accelerator Verdict |
| :--- | :--- | :--- |
| **Zone 1 & 2 are clean (0% loss)**, but miHoYo targets exhibit 15–50%+ packet loss and 350ms+ latency spikes (especially between 19:00–23:00 CST). | **Public ChinaNet 163 gateway saturation / GFW throttling** | **BUY ACCELERATOR.** A booster's dedicated CN2 GIA / SD-WAN enterprise line bypasses this public gateway. |
| **Zone 1 (Local Gateway) has $\ge 5\%$ loss or high jitter** concurrently with game lag spikes. | **Local Wi-Fi / Router bufferbloat / Local ISP modem fault** | **DO NOT BUY.** An accelerator cannot fix local Wi-Fi drops. Switch to Ethernet or restart modem. |
| **All hops route cleanly to China**, but the target miHoYo IP drops 100% of packets uniformly across all hours. | **Server-side Anti-DDoS blackhole or official game maintenance** | **DO NOT BUY.** The destination host is offline or under mitigation. |

---

## Configuration (`config.json`)

```json
{
  "launcher_games_dir": "D:\\Program Files\\miHoYo Launcher\\games",
  "sampling": {
    "interval_seconds": 20,
    "ping_burst_count": 5,
    "ping_timeout_ms": 1000,
    "tcp_timeout_ms": 2000
  },
  "targets": {
    "local_gateway": "auto",
    "global_control": "1.1.1.1",
    "asia_transit_control": "20.210.150.1",
    "mihoyo_endpoints": [
      { "name": "Aliyun-AntiDDoS-1", "host": "203.107.36.87", "port": 443 },
      { "name": "Aliyun-AntiDDoS-2", "host": "203.107.60.77", "port": 443 },
      { "name": "Kunlun-CDN", "host": "122.156.129.54", "port": 80 }
    ]
  },
  "anomaly_trigger": {
    "loss_threshold_pct": 20.0,
    "rtt_spike_threshold_ms": 80.0,
    "trace_cooldown_seconds": 300,
    "max_hops": 25
  },
  "paths": {
    "log_file": "logs/connectivity.csv",
    "trace_dir": "traces",
    "report_dir": "reports"
  }
}
```
