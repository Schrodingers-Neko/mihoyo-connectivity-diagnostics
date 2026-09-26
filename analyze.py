"""
Decision Engine and Log Analyzer for miHoYo Connectivity Diagnostics.
Parses logs/connectivity.csv and traces/, evaluates performance deltas
between China Peak Hours (19:00-23:00 CST) and Off-Peak, and generates
a definitive buying recommendation for game accelerators.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def safe_float(val: Any, default: float = 0.0) -> float:
    try:
        f = float(val)
        return f if not math.isnan(f) else default
    except (ValueError, TypeError):
        return default


def safe_int(val: Any, default: int = 0) -> int:
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def find_log_files(log_path: str | None = None, log_dir: str = "logs", load_all: bool = False) -> list[Path]:
    """Find specific log file, all log files, or the latest timestamped log file."""
    if log_path:
        p = Path(log_path)
        return [p] if p.is_file() else []

    dir_path = Path(log_dir)
    if not dir_path.is_dir():
        return []

    files = list(dir_path.glob("connectivity*.csv"))
    if not files:
        legacy = dir_path / "connectivity.csv"
        return [legacy] if legacy.is_file() else []

    # Sort descending by modified time (latest first)
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    if load_all:
        return files
    return [files[0]]


class ConnectivityAnalyzer:
    def __init__(
        self,
        log_path: str | None = None,
        trace_dir: str = "traces",
        load_all: bool = False,
    ) -> None:
        self.trace_dir = Path(trace_dir)
        self.source_files = find_log_files(log_path=log_path, load_all=load_all)
        self.records: list[dict[str, Any]] = []
        self._load_records()

    def _load_records(self) -> None:
        for fpath in self.source_files:
            if not fpath.is_file():
                continue
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    self.records.append({
                    "timestamp_local": row.get("timestamp_local", ""),
                    "timestamp_cst": row.get("timestamp_cst", ""),
                    "cst_hour": safe_int(row.get("cst_hour")),
                    "is_cst_peak": row.get("is_cst_peak", "False").lower() == "true",
                    "active_game": row.get("active_game", "None"),
                    "target_name": row.get("target_name", ""),
                    "target_host": row.get("target_host", ""),
                    "target_type": row.get("target_type", ""),
                    "packets_sent": safe_int(row.get("packets_sent")),
                    "packets_recv": safe_int(row.get("packets_recv")),
                    "loss_pct": safe_float(row.get("loss_pct")),
                    "min_rtt_ms": safe_float(row.get("min_rtt_ms"), -1.0),
                    "avg_rtt_ms": safe_float(row.get("avg_rtt_ms"), -1.0),
                    "max_rtt_ms": safe_float(row.get("max_rtt_ms"), -1.0),
                    "jitter_ms": safe_float(row.get("jitter_ms"), -1.0),
                    "tcp_port": safe_int(row.get("tcp_port")),
                    "tcp_success": row.get("tcp_success", "False").lower() == "true",
                    "tcp_handshake_ms": safe_float(row.get("tcp_handshake_ms"), -1.0),
                    "anomaly_triggered": row.get("anomaly_triggered", "False").lower() == "true",
                })

    def aggregate_by_target(self) -> dict[str, dict[str, Any]]:
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for r in self.records:
            groups[r["target_name"]].append(r)

        result = {}
        for name, rows in groups.items():
            sent = sum(r["packets_sent"] for r in rows)
            recv = sum(r["packets_recv"] for r in rows)
            loss_pct = round(((sent - recv) / sent * 100.0), 1) if sent > 0 else 0.0

            valid_rtts = [r["avg_rtt_ms"] for r in rows if r["avg_rtt_ms"] >= 0]
            avg_rtt = round(sum(valid_rtts) / len(valid_rtts), 1) if valid_rtts else -1.0
            min_rtt = min([r["min_rtt_ms"] for r in rows if r["min_rtt_ms"] >= 0], default=-1.0)
            max_rtt = max([r["max_rtt_ms"] for r in rows if r["max_rtt_ms"] >= 0], default=-1.0)

            valid_jitters = [r["jitter_ms"] for r in rows if r["jitter_ms"] >= 0]
            avg_jitter = round(sum(valid_jitters) / len(valid_jitters), 1) if valid_jitters else -1.0

            tcp_rows = [r for r in rows if r["tcp_port"] > 0]
            tcp_ok = sum(1 for r in tcp_rows if r["tcp_success"])
            tcp_rate = round(tcp_ok / len(tcp_rows) * 100.0, 1) if tcp_rows else 100.0
            valid_tcps = [r["tcp_handshake_ms"] for r in tcp_rows if r["tcp_success"] and r["tcp_handshake_ms"] >= 0]
            avg_tcp = round(sum(valid_tcps) / len(valid_tcps), 1) if valid_tcps else -1.0

            # Peak vs Off-Peak splits
            peak_rows = [r for r in rows if r["is_cst_peak"]]
            offpeak_rows = [r for r in rows if not r["is_cst_peak"]]

            peak_sent = sum(r["packets_sent"] for r in peak_rows)
            peak_recv = sum(r["packets_recv"] for r in peak_rows)
            peak_loss = round((peak_sent - peak_recv) / peak_sent * 100.0, 1) if peak_sent > 0 else 0.0

            offpeak_sent = sum(r["packets_sent"] for r in offpeak_rows)
            offpeak_recv = sum(r["packets_recv"] for r in offpeak_rows)
            offpeak_loss = round((offpeak_sent - offpeak_recv) / offpeak_sent * 100.0, 1) if offpeak_sent > 0 else 0.0

            result[name] = {
                "target_type": rows[0]["target_type"],
                "target_host": rows[0]["target_host"],
                "samples": len(rows),
                "loss_pct": loss_pct,
                "avg_rtt_ms": avg_rtt,
                "min_rtt_ms": min_rtt,
                "max_rtt_ms": max_rtt,
                "avg_jitter_ms": avg_jitter,
                "tcp_rate": tcp_rate,
                "avg_tcp_ms": avg_tcp,
                "peak_samples": len(peak_rows),
                "peak_loss": peak_loss,
                "offpeak_samples": len(offpeak_rows),
                "offpeak_loss": offpeak_loss,
            }
        return result

    def evaluate_decision_matrix(self) -> dict[str, Any]:
        """Evaluate telemetry data against the Go/No-Go buying decision criteria."""
        stats = self.aggregate_by_target()
        total_samples = len(self.records)

        if total_samples < 5:
            return {
                "verdict": "INSUFFICIENT_DATA",
                "badge": "NEED MORE DATA",
                "summary": "Fewer than 5 diagnostic samples collected so far.",
                "details": [
                    "Keep `monitor.py` running for at least 1-2 hours (ideally across China peak hours 19:00-23:00 CST / 07:00-11:00 EDT) to accumulate statistical significance."
                ],
                "action": "Let the monitor continue running.",
            }

        local_stat = stats.get("Local-Gateway", {})
        global_stat = stats.get("Global-Cloudflare", {})
        transit_stat = stats.get("Transit-AsiaEast", {})

        local_loss = local_stat.get("loss_pct", 0.0)
        local_jitter = local_stat.get("avg_jitter_ms", 0.0)
        global_loss = global_stat.get("loss_pct", 0.0)

        # miHoYo nodes analysis
        mihoyo_stats = [v for k, v in stats.items() if v["target_type"].startswith("mihoyo")]
        if not mihoyo_stats:
            return {
                "verdict": "NO_MIHOYO_TARGETS",
                "badge": "CONFIG ERROR",
                "summary": "No miHoYo target statistics available.",
                "details": [],
                "action": "Check config.json targets.",
            }

        avg_mihoyo_loss = sum(m["loss_pct"] for m in mihoyo_stats) / len(mihoyo_stats)
        avg_mihoyo_peak_loss = (
            sum(m["peak_loss"] for m in mihoyo_stats) / len(mihoyo_stats)
        )
        avg_mihoyo_offpeak_loss = (
            sum(m["offpeak_loss"] for m in mihoyo_stats) / len(mihoyo_stats)
        )
        avg_mihoyo_rtt = (
            sum(m["avg_rtt_ms"] for m in mihoyo_stats if m["avg_rtt_ms"] > 0)
            / max(1, sum(1 for m in mihoyo_stats if m["avg_rtt_ms"] > 0))
        )

        anomalies_logged = sum(1 for r in self.records if r["anomaly_triggered"])
        saved_traces = list(self.trace_dir.glob("*.txt"))

        # Rule 1: Local network issue
        if local_loss >= 5.0 or local_jitter >= 15.0:
            return {
                "verdict": "DO_NOT_BUY_LOCAL_FAULT",
                "badge": "DO NOT BUY (LOCAL FAULT)",
                "summary": f"Local network fault detected: Local Gateway has {local_loss}% loss and {local_jitter}ms jitter.",
                "details": [
                    f"Your Wi-Fi or home router is dropping packets ({local_loss}% loss) before reaching the internet.",
                    "An accelerator cannot fix local packet loss. Connect via Ethernet cable or restart your router/modem.",
                ],
                "action": "Fix local Wi-Fi / LAN connection first.",
            }

        # Rule 2: Cross-border 163 congestion (Peak vs Off-peak delta)
        # If miHoYo loss is prominent during peak hours while local & global are clean
        peak_delta = avg_mihoyo_peak_loss - avg_mihoyo_offpeak_loss
        differential_loss = avg_mihoyo_loss - max(local_loss, global_loss)

        total_peak_samples = sum(m["peak_samples"] for m in mihoyo_stats)
        peak_str = (
            f"Spiking to {avg_mihoyo_peak_loss:.1f}% during CST Peak hours"
            if total_peak_samples > 0
            else "Off-peak samples only; CST peak hours are 19:00-23:00 CST"
        )

        if (
            (avg_mihoyo_peak_loss >= 10.0 and peak_delta >= 8.0)
            or (differential_loss >= 12.0 and local_loss < 2.0)
            or (anomalies_logged >= 2 and local_loss < 2.0)
        ):
            return {
                "verdict": "BUY_ACCELERATOR",
                "badge": "RECOMMENDED: BUY ACCELERATOR",
                "summary": "Cross-border ChinaNet 163 public gateway congestion & throttling verified.",
                "details": [
                    f"Local and global controls are clean (Local loss: {local_loss}%, Global loss: {global_loss}%).",
                    f"miHoYo targets experience {avg_mihoyo_loss:.1f}% average packet loss ({peak_str}).",
                    f"Recorded {anomalies_logged} severe route degradation event(s).",
                    "A dedicated game accelerator (NetEase UU or Leigod) using private CN2 GIA/SD-WAN lines will bypass this public gateway bottleneck.",
                ],
                "action": "Proceed with NetEase UU (网易UU) or Leigod (雷神) subscription.",
            }

        # Rule 3: Pristine connection
        if avg_mihoyo_loss < 3.0 and avg_mihoyo_rtt > 0 and avg_mihoyo_rtt < 260.0:
            return {
                "verdict": "DO_NOT_BUY_EXCELLENT_CONNECTION",
                "badge": "DO NOT BUY (CONNECTION IS HEALTHY)",
                "summary": f"Your direct connection to miHoYo China is currently healthy (Loss: {avg_mihoyo_loss:.1f}%, Avg RTT: {avg_mihoyo_rtt:.1f}ms).",
                "details": [
                    f"Packet loss is low ({avg_mihoyo_loss:.1f}%), within playable thresholds.",
                    "Latency is near the physical speed-of-light floor for cross-border fiber.",
                    "No subscription needed unless connectivity degrades during specific hours.",
                ],
                "action": "Hold off on buying; re-check if lag spikes reoccur.",
            }

        # Default fallback: Mild degradation or indeterminate
        return {
            "verdict": "MONITORING_SUGGESTED",
            "badge": "BORDERLINE / CONTINUE MONITORING",
            "summary": f"Mild packet loss detected ({avg_mihoyo_loss:.1f}%), but below definitive threshold.",
            "details": [
                f"Local network is stable ({local_loss}% loss).",
                f"miHoYo average latency is {avg_mihoyo_rtt:.1f}ms with {avg_mihoyo_loss:.1f}% loss.",
                "Run monitor during your usual gaming sessions to see if game combat feels desynced.",
            ],
            "action": "Test a free trial of NetEase UU / Leigod if you experience in-game rubberbanding.",
        }

    def print_terminal_report(self) -> None:
        stats = self.aggregate_by_target()
        decision = self.evaluate_decision_matrix()

        print("\n" + "=" * 78)
        print("  miHoYo Connectivity Diagnostic & Accelerator Decision Report")
        print("=" * 78)
        print(f"Total Probed Samples: {len(self.records)}")
        if self.records:
            first_ts = self.records[0]["timestamp_local"]
            last_ts = self.records[-1]["timestamp_local"]
            print(f"Monitoring Period:    {first_ts}  -->  {last_ts}")

        print("\n" + "-" * 78)
        print("  1. TARGET PERFORMANCE SUMMARY")
        print("-" * 78)

        headers = ["Target", "Host", "Loss%", "Avg RTT", "Jitter", "TCP%", "CST Peak Loss", "Off-Peak Loss"]
        col_w = [20, 16, 8, 10, 8, 8, 14, 14]
        h_line = " | ".join(h.ljust(col_w[i]) for i, h in enumerate(headers))
        s_line = "-+-".join("-" * col_w[i] for i in range(len(headers)))
        print(h_line)
        print(s_line)

        for name, s in stats.items():
            rtt_str = f"{s['avg_rtt_ms']} ms" if s["avg_rtt_ms"] >= 0 else "TIMEOUT"
            jitter_str = f"{s['avg_jitter_ms']} ms" if s["avg_jitter_ms"] >= 0 else "-"
            tcp_str = f"{s['tcp_rate']:.0f}%" if s["tcp_rate"] >= 0 else "N/A"
            peak_str = f"{s['peak_loss']:.1f}% ({s['peak_samples']})"
            offpeak_str = f"{s['offpeak_loss']:.1f}% ({s['offpeak_samples']})"

            row = [
                name,
                s["target_host"],
                f"{s['loss_pct']:.1f}%",
                rtt_str,
                jitter_str,
                tcp_str,
                peak_str,
                offpeak_str,
            ]
            print(" | ".join(cell.ljust(col_w[i]) for i, cell in enumerate(row)))

        print("\n" + "-" * 78)
        print("  2. ACCELERATOR BUYING VERDICT")
        print("-" * 78)
        print(f"\n >>> VERDICT: [ {decision['badge']} ] <<<\n")
        print(f"Summary: {decision['summary']}\n")
        print("Diagnostic Details:")
        for d in decision["details"]:
            print(f"  * {d}")
        print(f"\nRecommended Action: {decision['action']}\n")
        print("=" * 78)

    def generate_html_report(self, output_path: str | None = None) -> tuple[Path, Path]:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        if output_path:
            out_file = Path(output_path)
        else:
            out_file = Path(f"reports/summary_{ts}.html")

        out_file.parent.mkdir(parents=True, exist_ok=True)
        stats = self.aggregate_by_target()
        decision = self.evaluate_decision_matrix()

        badge_color = "#10b981" if "HEALTHY" in decision["badge"] else (
            "#ef4444" if "BUY ACCELERATOR" in decision["badge"] else "#f59e0b"
        )

        rows_html = ""
        for name, s in stats.items():
            rtt = f"{s['avg_rtt_ms']} ms" if s["avg_rtt_ms"] >= 0 else "TIMEOUT"
            jitter = f"{s['avg_jitter_ms']} ms" if s["avg_jitter_ms"] >= 0 else "-"
            loss_color = "#10b981" if s["loss_pct"] < 5 else ("#f59e0b" if s["loss_pct"] < 15 else "#ef4444")
            rows_html += f"""
            <tr>
                <td><strong>{name}</strong><br><small style="color:#64748b;">{s['target_host']}</small></td>
                <td><span style="color:{loss_color};font-weight:600;">{s['loss_pct']:.1f}%</span></td>
                <td>{rtt}</td>
                <td>{jitter}</td>
                <td>{s['tcp_rate']:.0f}%</td>
                <td>{s['peak_loss']:.1f}% <small style="color:#64748b;">({s['peak_samples']} samples)</small></td>
                <td>{s['offpeak_loss']:.1f}% <small style="color:#64748b;">({s['offpeak_samples']} samples)</small></td>
            </tr>
            """

        details_html = "".join(f"<li>{d}</li>" for d in decision["details"])
        source_files_str = ", ".join(f.name for f in self.source_files) if self.source_files else "None"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>miHoYo Connectivity Diagnostic Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 30px; }}
  .container {{ max-width: 1000px; margin: 0 auto; }}
  .card {{ background: #1e293b; border-radius: 12px; padding: 24px; margin-bottom: 24px; border: 1px solid #334155; }}
  h1 {{ margin-top: 0; font-size: 24px; color: #38bdf8; }}
  .badge {{ display: inline-block; padding: 6px 14px; border-radius: 9999px; font-weight: 700; font-size: 14px; background: {badge_color}; color: #ffffff; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
  th, td {{ text-align: left; padding: 12px 14px; border-bottom: 1px solid #334155; }}
  th {{ background: #0f172a; color: #94a3b8; font-size: 13px; text-transform: uppercase; letter-spacing: 0.05em; }}
  ul {{ padding-left: 20px; line-height: 1.6; color: #cbd5e1; }}
  .action-box {{ background: #0f172a; border-left: 4px solid #38bdf8; padding: 14px 18px; border-radius: 6px; margin-top: 16px; }}
  .meta {{ color: #94a3b8; font-size: 14px; margin-bottom: 20px; }}
</style>
</head>
<body>
<div class="container">
  <h1>miHoYo China Connectivity Diagnostic Report</h1>
  <div class="meta">
    Generated on: <strong>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} Local Time</strong> | 
    Source: <strong>{source_files_str}</strong> | Total Samples: <strong>{len(self.records)}</strong>
  </div>

  <div class="card">
    <div style="display:flex; justify-content:space-between; align-items:center;">
      <h2 style="margin:0; font-size:18px;">Buying Recommendation</h2>
      <span class="badge">{decision['badge']}</span>
    </div>
    <p style="font-size:16px; margin: 16px 0 8px 0;"><strong>{decision['summary']}</strong></p>
    <ul>{details_html}</ul>
    <div class="action-box">
      <strong>Recommended Action:</strong> {decision['action']}
    </div>
  </div>

  <div class="card">
    <h2 style="margin-top:0; font-size:18px;">Target Performance Metrics</h2>
    <table>
      <thead>
        <tr>
          <th>Target</th>
          <th>Loss %</th>
          <th>Avg RTT</th>
          <th>Jitter</th>
          <th>TCP 443 OK</th>
          <th>CST Peak Loss (19:00-23:00)</th>
          <th>Off-Peak Loss</th>
        </tr>
      </thead>
      <tbody>
        {rows_html}
      </tbody>
    </table>
  </div>
</div>
</body>
</html>"""
        out_file.write_text(html_content, encoding="utf-8")

        # Also write/update summary_latest.html for easy browser bookmarking
        latest_file = out_file.parent / "summary_latest.html"
        try:
            latest_file.write_text(html_content, encoding="utf-8")
        except Exception:
            pass

        return out_file, latest_file


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze connectivity logs and determine if an accelerator is recommended."
    )
    parser.add_argument(
        "--log",
        "-l",
        default=None,
        help="Path to specific CSV log file (default: auto-detect latest logs/connectivity_*.csv).",
    )
    parser.add_argument(
        "--all",
        "-a",
        action="store_true",
        help="Aggregate data across ALL CSV logs in logs/ directory.",
    )
    parser.add_argument(
        "--html",
        action="store_true",
        help="Generate timestamped HTML report in reports/summary_<timestamp>.html (and reports/summary_latest.html).",
    )
    parser.add_argument(
        "--output-html",
        default=None,
        help="Custom path for HTML report.",
    )
    args = parser.parse_args()

    analyzer = ConnectivityAnalyzer(log_path=args.log, load_all=args.all)
    if not analyzer.source_files:
        print("No connectivity log files found in logs/ directory.")
        print("Run `python monitor.py` first to collect diagnostic data.")
        return

    src_names = ", ".join(f.name for f in analyzer.source_files)
    print(f"[Loading telemetry from: {src_names}]")

    analyzer.print_terminal_report()

    if args.html:
        path, latest = analyzer.generate_html_report(output_path=args.output_html)
        print(f"Timestamped HTML report generated: {path}")
        print(f"Latest report bookmark updated:    {latest}")


if __name__ == "__main__":
    main()
