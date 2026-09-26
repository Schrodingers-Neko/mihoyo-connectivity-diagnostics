"""
Continuous Network Connectivity Diagnostic Probe for miHoYo China Game Servers.
Probes local control, global control, transit control, and miHoYo endpoints concurrently.
Tags metrics with China Standard Time (CST), detects active game sessions, and
triggers rate-limited traceroute snapshots when anomalies are detected.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from game_discovery import (
    get_game_connections,
    get_running_games,
    load_tracked_games,
)

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
        sys.stderr.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    except Exception:
        pass

CST_TZ = timezone(timedelta(hours=8))

CSV_HEADERS = [
    "timestamp_local",
    "timestamp_cst",
    "cst_hour",
    "is_cst_peak",
    "active_game",
    "target_name",
    "target_host",
    "target_type",
    "packets_sent",
    "packets_recv",
    "loss_pct",
    "min_rtt_ms",
    "avg_rtt_ms",
    "max_rtt_ms",
    "jitter_ms",
    "tcp_port",
    "tcp_success",
    "tcp_handshake_ms",
    "anomaly_triggered",
]


def detect_local_gateway() -> str:
    """Find the default IPv4 gateway via route print."""
    try:
        out = subprocess.check_output(
            ["route", "print", "0.0.0.0"],
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
        for line in out.splitlines():
            m = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", line)
            if m:
                gw = m.group(1)
                if not gw.startswith("127.") and gw != "0.0.0.0":
                    return gw
    except Exception:
        pass
    return "192.168.1.1"


async def ping_target(host: str, burst_count: int, timeout_ms: int) -> dict[str, Any]:
    """Execute ping command asynchronously and extract burst statistics."""
    cmd = ["ping", "-n", str(burst_count), "-w", str(timeout_ms), host]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        out = stdout.decode("utf-8", errors="ignore")
    except Exception:
        return {
            "sent": burst_count,
            "recv": 0,
            "loss_pct": 100.0,
            "min_rtt": -1.0,
            "avg_rtt": -1.0,
            "max_rtt": -1.0,
            "jitter": -1.0,
        }

    # Extract individual packet latencies (works across English and localized Windows)
    rtts = []
    for match in re.finditer(r"time[=<](\d+)ms", out, re.IGNORECASE):
        try:
            rtts.append(float(match.group(1)))
        except ValueError:
            pass

    sent = burst_count
    recv = len(rtts)
    loss_pct = 100.0

    m_stat = re.search(r"Sent\s*=\s*(\d+),\s*Received\s*=\s*(\d+)", out, re.IGNORECASE)
    if m_stat:
        sent = int(m_stat.group(1))
        recv = int(m_stat.group(2))

    if sent > 0:
        loss_pct = round(((sent - recv) / sent) * 100.0, 1)

    min_rtt = -1.0
    avg_rtt = -1.0
    max_rtt = -1.0
    jitter = -1.0

    if rtts:
        min_rtt = min(rtts)
        max_rtt = max(rtts)
        avg_rtt = round(sum(rtts) / len(rtts), 1)
        jitter = round(max_rtt - min_rtt, 1)
    else:
        m_times = re.search(
            r"Minimum\s*=\s*(\d+)ms,\s*Maximum\s*=\s*(\d+)ms,\s*Average\s*=\s*(\d+)ms",
            out,
            re.IGNORECASE,
        )
        if m_times:
            min_rtt = float(m_times.group(1))
            max_rtt = float(m_times.group(2))
            avg_rtt = float(m_times.group(3))
            jitter = round(max_rtt - min_rtt, 1)

    return {
        "sent": sent,
        "recv": recv,
        "loss_pct": loss_pct,
        "min_rtt": min_rtt,
        "avg_rtt": avg_rtt,
        "max_rtt": max_rtt,
        "jitter": jitter,
    }


def _sync_tcp_probe(host: str, port: int, timeout_sec: float) -> tuple[bool, float]:
    """Synchronous socket connection probe measuring SYN-ACK RTT."""
    if not port or port <= 0:
        return False, -1.0
    start = time.perf_counter()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout_sec)
        s.connect((host, port))
        elapsed = (time.perf_counter() - start) * 1000.0
        s.close()
        return True, round(elapsed, 1)
    except Exception:
        return False, -1.0


async def test_tcp_handshake(host: str, port: int, timeout_ms: int) -> tuple[bool, float]:
    """Perform non-blocking TCP 3-way handshake measurement."""
    return await asyncio.to_thread(_sync_tcp_probe, host, port, timeout_ms / 1000.0)


def _run_tracert_thread(host: str, target_name: str, max_hops: int, trace_dir: Path) -> None:
    """Run traceroute in a background daemon thread without blocking the async loop."""
    try:
        trace_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", target_name)
        out_file = trace_dir / f"trace_{ts}_{safe_name}_{host}.txt"

        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", "1000", host]
        res = subprocess.run(cmd, capture_output=True, text=True, errors="ignore")
        header = f"# Automated Trace Snapshot for {target_name} ({host})\n# Generated at {datetime.now().isoformat()}\n\n"
        out_file.write_text(header + res.stdout, encoding="utf-8")
        print(f"[✓] Traceroute snapshot saved: {out_file.name}")
    except Exception as e:
        print(f"[!] Traceroute failed for {host}: {e}", file=sys.stderr)


class NetworkMonitor:
    def __init__(self, config_path: str = "config.json", log_path: str | None = None) -> None:
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.trace_dir = Path(self.config.get("paths", {}).get("trace_dir", "traces"))
        self.last_trace_time: dict[str, float] = {}
        self.global_last_trace_time: float = 0.0
        self.tracked_games = load_tracked_games(self.config_path)

        if log_path:
            self.log_file = Path(log_path)
        else:
            paths_cfg = self.config.get("paths", {})
            template = paths_cfg.get(
                "log_file_template",
                paths_cfg.get("log_file", "logs/connectivity_{timestamp}.csv"),
            )
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            rendered = template.replace("{timestamp}", ts)
            self.log_file = Path(rendered)

        self._init_csv()

    def _load_config(self) -> dict[str, Any]:
        if not self.config_path.is_file():
            raise FileNotFoundError(f"Config file not found: {self.config_path}")
        with open(self.config_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _init_csv(self) -> None:
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.log_file.is_file() or self.log_file.stat().st_size == 0:
            with open(self.log_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(CSV_HEADERS)

    def resolve_targets(self, include_live_game_ips: bool = True) -> list[dict[str, Any]]:
        """Build target list, resolving auto gateway and running game endpoints."""
        raw_targets = self.config.get("targets", {})
        targets = []

        # Local Gateway
        gw = raw_targets.get("local_gateway", "auto")
        if gw == "auto":
            gw = detect_local_gateway()
        targets.append({
            "name": "Local-Gateway",
            "host": gw,
            "type": "control_local",
            "port": 0,
        })

        # Global Control
        gc = raw_targets.get("global_control", "1.1.1.1")
        targets.append({
            "name": "Global-Cloudflare",
            "host": gc,
            "type": "control_global",
            "port": 53,
        })

        # Asia Pacific Transit Control
        asia = raw_targets.get("asia_transit_control", "20.210.150.1")
        targets.append({
            "name": "Transit-AsiaEast",
            "host": asia,
            "type": "control_transit",
            "port": 443,
        })

        # Configured miHoYo Endpoints
        for ep in raw_targets.get("mihoyo_endpoints", []):
            targets.append({
                "name": ep.get("name", "miHoYo-Node"),
                "host": ep["host"],
                "type": "mihoyo_edge",
                "port": ep.get("port", 443),
            })

        # Dynamically discover running game active server socket IPs
        if include_live_game_ips:
            running = get_running_games(config_path=self.config_path, tracked_games=self.tracked_games)
            if running:
                conns = get_game_connections(running)
                seen_hosts = {t["host"] for t in targets}
                for c in conns:
                    ip = c["remote_ip"]
                    if ip not in seen_hosts:
                        seen_hosts.add(ip)
                        short_name = c["game_name"].split()[0]
                        targets.append({
                            "name": f"LiveGame-{short_name}-{c['protocol']}",
                            "host": ip,
                            "type": "mihoyo_live_game",
                            "port": c["remote_port"] if c["protocol"] == "TCP" else 0,
                        })

        return targets

    def get_current_active_game_label(self) -> str:
        """Return the name of currently running game or 'None'."""
        running = get_running_games(config_path=self.config_path, tracked_games=self.tracked_games)
        if not running:
            return "None"
        names = [r["game_name"].split()[0] for r in running]
        return "+".join(sorted(set(names)))

    async def probe_cycle(self, trigger_traces: bool = True) -> list[dict[str, Any]]:
        """Run one complete cycle of probes concurrently across all targets."""
        sampling = self.config.get("sampling", {})
        burst_count = sampling.get("ping_burst_count", 5)
        ping_timeout = sampling.get("ping_timeout_ms", 1000)
        tcp_timeout = sampling.get("tcp_timeout_ms", 2000)

        targets = self.resolve_targets(include_live_game_ips=True)
        active_game = self.get_current_active_game_label()

        now_local = datetime.now()
        now_cst = datetime.now(CST_TZ)
        cst_hour = now_cst.hour
        is_cst_peak = 19 <= cst_hour <= 23

        # Launch all ping and TCP tasks concurrently
        ping_tasks = [ping_target(t["host"], burst_count, ping_timeout) for t in targets]
        tcp_tasks = [test_tcp_handshake(t["host"], t["port"], tcp_timeout) for t in targets]

        ping_results = await asyncio.gather(*ping_tasks)
        tcp_results = await asyncio.gather(*tcp_tasks)

        cycle_data = []
        for i, t in enumerate(targets):
            p_res = ping_results[i]
            tcp_ok, tcp_rtt = tcp_results[i]

            entry = {
                "timestamp_local": now_local.strftime("%Y-%m-%d %H:%M:%S"),
                "timestamp_cst": now_cst.strftime("%Y-%m-%d %H:%M:%S"),
                "cst_hour": cst_hour,
                "is_cst_peak": is_cst_peak,
                "active_game": active_game,
                "target_name": t["name"],
                "target_host": t["host"],
                "target_type": t["type"],
                "packets_sent": p_res["sent"],
                "packets_recv": p_res["recv"],
                "loss_pct": p_res["loss_pct"],
                "min_rtt_ms": p_res["min_rtt"],
                "avg_rtt_ms": p_res["avg_rtt"],
                "max_rtt_ms": p_res["max_rtt"],
                "jitter_ms": p_res["jitter"],
                "tcp_port": t["port"],
                "tcp_success": tcp_ok,
                "tcp_handshake_ms": tcp_rtt,
                "anomaly_triggered": False,
            }
            cycle_data.append(entry)

        # Check for degradation anomalies
        if trigger_traces:
            self._evaluate_anomalies(cycle_data)

        # Append to CSV
        self._save_to_csv(cycle_data)

        return cycle_data

    def _evaluate_anomalies(self, cycle_data: list[dict[str, Any]]) -> None:
        """Detect if miHoYo edge targets degraded while local gateway is healthy."""
        anomaly_cfg = self.config.get("anomaly_trigger", {})
        loss_thresh = anomaly_cfg.get("loss_threshold_pct", 20.0)
        cooldown = anomaly_cfg.get("trace_cooldown_seconds", 300)
        max_hops = anomaly_cfg.get("max_hops", 25)

        # Find local gateway loss
        local_loss = 0.0
        for row in cycle_data:
            if row["target_type"] == "control_local":
                local_loss = row["loss_pct"]
                break

        # If local gateway is dropping packets, local network is the root cause
        if local_loss >= 10.0:
            return

        now_ts = time.time()
        # Enforce global cooldown across all traceroutes
        if now_ts - self.global_last_trace_time < cooldown:
            return

        for row in cycle_data:
            # Only trigger on miHoYo edge infrastructure (avoid false alarms on UDP game server ping drops)
            if row["target_type"] == "mihoyo_edge":
                loss = row["loss_pct"]
                avg_rtt = row["avg_rtt_ms"]
                host = row["target_host"]
                name = row["target_name"]

                is_anomaly = (loss >= loss_thresh) or (avg_rtt > 0 and avg_rtt >= 300.0)
                if is_anomaly:
                    last_time = self.last_trace_time.get(host, 0.0)
                    if now_ts - last_time >= cooldown:
                        self.last_trace_time[host] = now_ts
                        self.global_last_trace_time = now_ts
                        row["anomaly_triggered"] = True
                        print(
                            f"\n[!] ANOMALY DETECTED on {name} ({host}): Loss={loss}%, AvgRTT={avg_rtt}ms. "
                            f"Spawning background traceroute snapshot..."
                        )
                        t = threading.Thread(
                            target=_run_tracert_thread,
                            args=(host, name, max_hops, self.trace_dir),
                            daemon=True,
                        )
                        t.start()
                        break  # Launch at most 1 traceroute per cycle

    def _save_to_csv(self, cycle_data: list[dict[str, Any]]) -> None:
        """Append rows to CSV file with flush."""
        try:
            with open(self.log_file, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                for r in cycle_data:
                    writer.writerow([
                        r["timestamp_local"],
                        r["timestamp_cst"],
                        r["cst_hour"],
                        r["is_cst_peak"],
                        r["active_game"],
                        r["target_name"],
                        r["target_host"],
                        r["target_type"],
                        r["packets_sent"],
                        r["packets_recv"],
                        r["loss_pct"],
                        r["min_rtt_ms"],
                        r["avg_rtt_ms"],
                        r["max_rtt_ms"],
                        r["jitter_ms"],
                        r["tcp_port"],
                        r["tcp_success"],
                        r["tcp_handshake_ms"],
                        r["anomaly_triggered"],
                    ])
                f.flush()
        except Exception as e:
            print(f"Error saving to CSV: {e}", file=sys.stderr)


def print_cycle_summary(cycle_data: list[dict[str, Any]]) -> None:
    """Print clean formatted table of current cycle results."""
    first = cycle_data[0]
    peak_str = "YES (Peak Congestion Window)" if first["is_cst_peak"] else "No (Off-Peak)"
    print(f"\n[{first['timestamp_local']} Local / {first['timestamp_cst']} CST] Peak: {peak_str} | Active Game: {first['active_game']}")

    headers = ["Target", "Host", "Loss%", "RTT (Min/Avg/Max)", "Jitter", "TCP Handshake"]
    col_w = [23, 16, 8, 22, 10, 15]

    header_line = " | ".join(h.ljust(col_w[i]) for i, h in enumerate(headers))
    sep_line = "-+-".join("-" * col_w[i] for i in range(len(headers)))
    print(header_line)
    print(sep_line)

    for r in cycle_data:
        rtt_str = (
            f"{int(r['min_rtt_ms'])}/{int(r['avg_rtt_ms'])}/{int(r['max_rtt_ms'])} ms"
            if r["avg_rtt_ms"] >= 0
            else "TIMEOUT"
        )
        jitter_str = f"{int(r['jitter_ms'])} ms" if r["jitter_ms"] >= 0 else "-"
        tcp_str = f"{int(r['tcp_handshake_ms'])} ms" if r["tcp_success"] else "FAIL"
        if r["tcp_port"] == 0:
            tcp_str = "N/A"

        row = [
            r["target_name"],
            r["target_host"],
            f"{r['loss_pct']:.0f}%",
            rtt_str,
            jitter_str,
            tcp_str,
        ]
        line = " | ".join(cell.ljust(col_w[i]) for i, cell in enumerate(row))
        print(line)


async def main_async() -> None:
    parser = argparse.ArgumentParser(
        description="Continuous network diagnostics monitor for miHoYo China servers."
    )
    parser.add_argument(
        "--config",
        "-c",
        default="config.json",
        help="Path to configuration file (default: config.json).",
    )
    parser.add_argument(
        "--log",
        "-l",
        default=None,
        help="Custom path for CSV log file (default: logs/connectivity_<timestamp>.csv).",
    )
    parser.add_argument(
        "--test-once",
        "-t",
        action="store_true",
        help="Run exactly one diagnostic cycle, print table, and exit.",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Run silently without printing each cycle table.",
    )
    args = parser.parse_args()

    monitor = NetworkMonitor(config_path=args.config, log_path=args.log)
    interval = monitor.config.get("sampling", {}).get("interval_seconds", 20)

    if args.test_once:
        print("Running single diagnostic self-test cycle...")
        cycle = await monitor.probe_cycle(trigger_traces=False)
        print_cycle_summary(cycle)
        print(f"\nTest cycle completed. Metric recorded to: {monitor.log_file}")
        return

    print("=" * 75)
    print(" miHoYo Connectivity Diagnostic Daemon Started")
    print(f" Logging interval: {interval}s | Destination: {monitor.log_file}")
    print(" Press Ctrl+C to terminate.")
    print("=" * 75)

    try:
        while True:
            cycle = await monitor.probe_cycle(trigger_traces=True)
            if not args.quiet:
                print_cycle_summary(cycle)
            await asyncio.sleep(interval)
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\nMonitoring stopped by user.")


def main() -> None:
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
