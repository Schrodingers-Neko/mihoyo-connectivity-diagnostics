"""
Decision Engine and Log Analyzer for miHoYo Connectivity Diagnostics.
Parses logs/connectivity*.csv and traces/, evaluates performance deltas
between China Peak Hours (19:00-23:00 CST) and Off-Peak, and generates
a definitive buying recommendation for game accelerators.
Generates bilingual HTML reports defaulting to zh-CN with an interactive en-US toggle.
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import math
import sys
import unicodedata
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


def cjk_display_width(val: Any) -> int:
    """Calculate monospaced terminal display width accounting for East Asian full-width characters."""
    width = 0
    for ch in str(val):
        w = unicodedata.east_asian_width(ch)
        width += 2 if w in ("W", "F") else 1
    return width


def cjk_ljust(val: Any, width: int) -> str:
    """Pad string to target terminal display width considering CJK characters."""
    s = str(val)
    cw = cjk_display_width(s)
    return s + (" " * max(0, width - cw))


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
        return []

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

    def get_trace_snapshots(self) -> list[Path]:
        """List available traceroute snapshot files in trace_dir."""
        if not self.trace_dir.is_dir():
            return []
        traces = list(self.trace_dir.glob("trace_*.txt"))
        traces.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        return traces

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

        # Ensure records are strictly ordered chronologically
        self.records.sort(key=lambda r: r.get("timestamp_local", ""))

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
                "badge_en": "NEED MORE DATA",
                "badge_zh": "数据积累不足",
                "summary_en": "Fewer than 5 diagnostic samples collected so far.",
                "summary_zh": "当前采集的诊断样本过少（少于 5 组）。",
                "details": [
                    {
                        "en": "Keep monitor.py running for at least 1-2 hours (ideally across China peak hours 19:00-23:00 CST) to accumulate statistical significance.",
                        "zh": "建议保持 monitor.py 后台运行 1~2 小时（尤其在北京时间 19:00~23:00 晚高峰期间）以积累充足统计样本。",
                    }
                ],
                "action_en": "Let the monitor continue running.",
                "action_zh": "让监控程序继续运行并积累样本。",
            }

        local_stat = stats.get("Local-Gateway", {})
        global_stat = stats.get("Global-Cloudflare", {})
        transit_stat = stats.get("Transit-AsiaEast", {})

        local_loss = local_stat.get("loss_pct", 0.0)
        local_jitter = local_stat.get("avg_jitter_ms", 0.0)
        global_loss = global_stat.get("loss_pct", 0.0)

        mihoyo_stats = [v for k, v in stats.items() if v["target_type"].startswith("mihoyo")]
        if not mihoyo_stats:
            return {
                "verdict": "NO_MIHOYO_TARGETS",
                "badge_en": "CONFIG ERROR",
                "badge_zh": "配置异常",
                "summary_en": "No miHoYo target statistics available.",
                "summary_zh": "未能获取到米哈游服务器目标的统计数据。",
                "details": [],
                "action_en": "Check config.json targets.",
                "action_zh": "请检查 config.json 中的目标配置。",
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

        # Rule 1: Local network issue
        if local_loss >= 5.0 or local_jitter >= 15.0:
            return {
                "verdict": "DO_NOT_BUY_LOCAL_FAULT",
                "badge_en": "DO NOT BUY (LOCAL FAULT)",
                "badge_zh": "无需购买 (本地局域网故障)",
                "summary_en": f"Local network fault detected: Local Gateway has {local_loss}% loss and {local_jitter}ms jitter.",
                "summary_zh": f"检测到本地网络异常：本地网关丢包率达 {local_loss}%，抖动 {local_jitter}ms。",
                "details": [
                    {
                        "en": f"Your Wi-Fi or home router is dropping packets ({local_loss}% loss) before traffic reaches the internet.",
                        "zh": f"数据包在出局前就已经在本地 Wi-Fi 或路由器端丢弃（本地丢包率 {local_loss}%）。",
                    },
                    {
                        "en": "An accelerator cannot fix local packet loss. Connect via Ethernet cable or restart your router/modem.",
                        "zh": "游戏加速器无法解决本地局域网物理丢包。建议优先更换有线以太网连接或重启光猫/路由器。",
                    },
                ],
                "action_en": "Fix local Wi-Fi / LAN connection first.",
                "action_zh": "优先排查并修复本地 Wi-Fi / 路由器有线连接。",
            }

        # Rule 2: Cross-border 163 congestion
        peak_delta = avg_mihoyo_peak_loss - avg_mihoyo_offpeak_loss
        differential_loss = avg_mihoyo_loss - max(local_loss, global_loss)

        total_peak_samples = sum(m["peak_samples"] for m in mihoyo_stats)
        peak_str_en = (
            f"Spiking to {avg_mihoyo_peak_loss:.1f}% during CST Peak hours"
            if total_peak_samples > 0
            else "Off-peak samples only; CST peak hours are 19:00-23:00 CST"
        )
        peak_str_zh = (
            f"中国晚高峰期间丢包飙升至 {avg_mihoyo_peak_loss:.1f}%"
            if total_peak_samples > 0
            else "当前仅含非高峰样本；中国晚高峰为北京时间 19:00~23:00"
        )

        if (
            (avg_mihoyo_peak_loss >= 10.0 and peak_delta >= 8.0)
            or (differential_loss >= 12.0 and local_loss < 2.0)
            or (anomalies_logged >= 2 and local_loss < 2.0)
        ):
            return {
                "verdict": "BUY_ACCELERATOR",
                "badge_en": "RECOMMENDED: BUY ACCELERATOR",
                "badge_zh": "建议购买加速器",
                "summary_en": "Cross-border ChinaNet 163 public gateway congestion & throttling verified.",
                "summary_zh": "已证实跨洋公共 ChinaNet 163 骨干网出入口存在严重拥堵与 QoS 审查限速。",
                "details": [
                    {
                        "en": f"Local and global controls are clean (Local loss: {local_loss}%, Global loss: {global_loss}%).",
                        "zh": f"本地与跨国控制组网络均健康纯净（本地丢包率: {local_loss}%，全局控制组丢包率: {global_loss}%）。",
                    },
                    {
                        "en": f"miHoYo targets experience {avg_mihoyo_loss:.1f}% average packet loss ({peak_str_en}).",
                        "zh": f"米哈游国服节点平均丢包率达 {avg_mihoyo_loss:.1f}%（{peak_str_zh}）。",
                    },
                    {
                        "en": f"Recorded {anomalies_logged} severe route degradation event(s).",
                        "zh": f"共捕获记录到 {anomalies_logged} 次严重路由劣化事件并已保存快照。",
                    },
                    {
                        "en": "A dedicated game accelerator (NetEase UU or Leigod) using private CN2 GIA/SD-WAN lines will bypass this public gateway bottleneck.",
                        "zh": "游戏加速器（网易UU或雷神加速器）使用的企业级 CN2 GIA / AS9929 / SD-WAN 专线可完全绕过公共 163 骨干网拥堵瓶颈。",
                    },
                ],
                "action_en": "Proceed with NetEase UU (网易UU) or Leigod (雷神) subscription.",
                "action_zh": "建议订购网易UU加速器或雷神加速器（可优先领取免费试用时长测试）。",
            }

        # Rule 3a: Pristine low-latency connection
        if avg_mihoyo_loss < 3.0 and avg_mihoyo_rtt > 0 and avg_mihoyo_rtt < 260.0:
            return {
                "verdict": "DO_NOT_BUY_EXCELLENT_CONNECTION",
                "badge_en": "DO NOT BUY (CONNECTION IS HEALTHY)",
                "badge_zh": "无需购买 (当前网络良好)",
                "summary_en": f"Your direct connection to miHoYo China is currently healthy (Loss: {avg_mihoyo_loss:.1f}%, Avg RTT: {avg_mihoyo_rtt:.1f}ms).",
                "summary_zh": f"当前直连米哈游国服网络表现优良（丢包率: {avg_mihoyo_loss:.1f}%，平均时延: {avg_mihoyo_rtt:.1f}ms）。",
                "details": [
                    {
                        "en": f"Packet loss is low ({avg_mihoyo_loss:.1f}%), within playable thresholds.",
                        "zh": f"丢包率维持在极低水准（{avg_mihoyo_loss:.1f}%），处于正常可游玩范围。",
                    },
                    {
                        "en": "Latency is near the physical speed-of-light floor for cross-border fiber.",
                        "zh": "时延接近跨国海底光缆物理光速极限。",
                    },
                    {
                        "en": "No subscription needed unless connectivity degrades during specific hours.",
                        "zh": "当前阶段无需购买加速器；如遇特定时段卡顿可随时重新发起诊断。",
                    },
                ],
                "action_en": "Hold off on buying; re-check if lag spikes reoccur.",
                "action_zh": "暂无须购买；待出现明显卡顿或重连时再行检测。",
            }

        # Rule 3b: Stable trans-oceanic route with high physical distance latency (e.g. US East to China)
        if avg_mihoyo_loss < 3.0 and avg_mihoyo_rtt >= 260.0:
            return {
                "verdict": "DO_NOT_BUY_HIGH_RTT_STABLE",
                "badge_en": "DO NOT BUY (STABLE HIGH RTT)",
                "badge_zh": "无需购买 (稳定物理远距延时)",
                "summary_en": f"Stable direct connection with expected long-distance trans-oceanic transit latency (Loss: {avg_mihoyo_loss:.1f}%, Avg RTT: {avg_mihoyo_rtt:.1f}ms).",
                "summary_zh": f"跨洋直连链路稳定，时延主要由地理物理距离所致（丢包率: {avg_mihoyo_loss:.1f}%，平均时延: {avg_mihoyo_rtt:.1f}ms）。",
                "details": [
                    {
                        "en": f"Packet loss is zero or minimal ({avg_mihoyo_loss:.1f}%), indicating clean transit queues without congested packet drops.",
                        "zh": f"丢包率接近零或极低（{avg_mihoyo_loss:.1f}%），表明骨干路由没有拥堵丢包。",
                    },
                    {
                        "en": f"High RTT ({avg_mihoyo_rtt:.1f}ms) reflects geographic distance across trans-Pacific fiber; an accelerator cannot beat the physical speed of light in glass.",
                        "zh": f"高时延（{avg_mihoyo_rtt:.1f}ms）系跨太平洋海底光缆物理传播距离所致；游戏加速器无法突破光纤光速物理极限。",
                    },
                    {
                        "en": "Accelerators only improve routing stability if packet loss or route flapping occurs during peak hours.",
                        "zh": "仅当晚高峰出现路由抖动或持续丢包时，加速器专线才有优化价值。",
                    },
                ],
                "action_en": "Play directly without accelerator; monitor during China peak hours (19:00-23:00 CST).",
                "action_zh": "可直接裸连游玩；建议在北京时间晚高峰（19:00~23:00）再次观测是否有拥堵丢包。",
            }

        # Default fallback: Mild degradation
        loss_desc_en = (
            f"Mild packet loss detected ({avg_mihoyo_loss:.1f}%), but below definitive threshold."
            if avg_mihoyo_loss > 0.0
            else f"Borderline metrics observed (Avg RTT: {avg_mihoyo_rtt:.1f}ms, Loss: {avg_mihoyo_loss:.1f}%)."
        )
        loss_desc_zh = (
            f"检测到轻度丢包与波动（{avg_mihoyo_loss:.1f}%），未达购买必要阈值。"
            if avg_mihoyo_loss > 0.0
            else f"检测到边界指标状态（平均时延: {avg_mihoyo_rtt:.1f}ms，丢包率: {avg_mihoyo_loss:.1f}%）。"
        )
        return {
            "verdict": "MONITORING_SUGGESTED",
            "badge_en": "BORDERLINE / CONTINUE MONITORING",
            "badge_zh": "中度波动 / 建议继续观察",
            "summary_en": loss_desc_en,
            "summary_zh": loss_desc_zh,
            "details": [
                {
                    "en": f"Local network is stable ({local_loss}% loss).",
                    "zh": f"本地网络保持稳定（{local_loss}% 丢包）。",
                },
                {
                    "en": f"miHoYo average latency is {avg_mihoyo_rtt:.1f}ms with {avg_mihoyo_loss:.1f}% loss.",
                    "zh": f"米哈游目标节点平均时延为 {avg_mihoyo_rtt:.1f}ms，丢包率为 {avg_mihoyo_loss:.1f}%。",
                },
                {
                    "en": "Run monitor during your usual gaming sessions to see if game combat feels desynced.",
                    "zh": "建议在实际游戏游玩期间保持后台监控，观察战斗切人是否存在卡顿脱节。",
                },
            ],
            "action_en": "Test a free trial of NetEase UU / Leigod if you experience in-game rubberbanding.",
            "action_zh": "如游戏中感知到明显脱节卡顿，可先尝试网易UU或雷神的免费试用时长。",
        }

    def print_terminal_report(self) -> None:
        stats = self.aggregate_by_target()
        decision = self.evaluate_decision_matrix()

        print("\n" + "=" * 78)
        print("  miHoYo Connectivity Diagnostic & Accelerator Decision Report")
        print("  米哈游国服网络连通性诊断与加速器选购评估报告")
        print("=" * 78)
        print(f"Total Probed Samples: {len(self.records)}")
        if self.records:
            first_ts = self.records[0]["timestamp_local"]
            last_ts = self.records[-1]["timestamp_local"]
            print(f"Monitoring Period:    {first_ts}  -->  {last_ts}")

        print("\n" + "-" * 78)
        print("  1. TARGET PERFORMANCE SUMMARY / 目标节点性能摘要")
        print("-" * 78)

        headers = ["Target", "Host", "Loss%", "Avg RTT", "Jitter", "TCP%", "CST Peak Loss", "Off-Peak Loss"]
        col_w = [22, 16, 8, 10, 8, 8, 14, 14]
        h_line = " | ".join(cjk_ljust(h, col_w[i]) for i, h in enumerate(headers))
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
            print(" | ".join(cjk_ljust(cell, col_w[i]) for i, cell in enumerate(row)))

        print("\n" + "-" * 78)
        print("  2. ACCELERATOR BUYING VERDICT / 选购评估结论")
        print("-" * 78)
        badge_en = decision.get("badge_en", decision.get("badge", ""))
        badge_zh = decision.get("badge_zh", "")
        print(f"\n >>> VERDICT: [ {badge_zh} | {badge_en} ] <<<\n")
        print(f"Summary (ZH): {decision.get('summary_zh', '')}")
        print(f"Summary (EN): {decision.get('summary_en', '')}\n")
        print("Diagnostic Details:")
        for d in decision.get("details", []):
            if isinstance(d, dict):
                print(f"  * [ZH] {d.get('zh', '')}")
                print(f"    [EN] {d.get('en', '')}")
            else:
                print(f"  * {d}")
        print(f"\nRecommended Action (ZH): {decision.get('action_zh', '')}")
        print(f"Recommended Action (EN): {decision.get('action_en', '')}\n")

        traces = self.get_trace_snapshots()
        if traces:
            print("-" * 78)
            print(f"  3. TRACEROUTE SNAPSHOTS / 路由诊断快照 ({len(traces)} captured)")
            print("-" * 78)
            for t in traces[:3]:
                print(f"  * {t.name}")
            if len(traces) > 3:
                print(f"    ... and {len(traces) - 3} more snapshot(s) in {self.trace_dir}/")
            print()
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

        badge_en = html.escape(str(decision.get("badge_en", "")))
        badge_zh = html.escape(str(decision.get("badge_zh", "")))
        summary_en = html.escape(str(decision.get("summary_en", "")))
        summary_zh = html.escape(str(decision.get("summary_zh", "")))
        action_en = html.escape(str(decision.get("action_en", "")))
        action_zh = html.escape(str(decision.get("action_zh", "")))

        badge_color = "#10b981" if "HEALTHY" in badge_en else (
            "#ef4444" if "BUY ACCELERATOR" in badge_en else "#f59e0b"
        )

        rows_html = ""
        for name, s in stats.items():
            rtt = f"{s['avg_rtt_ms']} ms" if s["avg_rtt_ms"] >= 0 else "TIMEOUT"
            jitter = f"{s['avg_jitter_ms']} ms" if s["avg_jitter_ms"] >= 0 else "-"
            loss_color = "#10b981" if s["loss_pct"] < 5 else ("#f59e0b" if s["loss_pct"] < 15 else "#ef4444")
            tcp_display = f"{s['tcp_rate']:.0f}%" if s["tcp_rate"] >= 0 else "N/A"
            safe_name = html.escape(str(name))
            safe_host = html.escape(str(s['target_host']))
            rows_html += f"""
            <tr>
                <td><strong>{safe_name}</strong><br><small style="color:#64748b;">{safe_host}</small></td>
                <td><span style="color:{loss_color};font-weight:600;">{s['loss_pct']:.1f}%</span></td>
                <td>{rtt}</td>
                <td>{jitter}</td>
                <td>{tcp_display}</td>
                <td>{s['peak_loss']:.1f}% <small style="color:#64748b;">({s['peak_samples']})</small></td>
                <td>{s['offpeak_loss']:.1f}% <small style="color:#64748b;">({s['offpeak_samples']})</small></td>
            </tr>
            """

        details_html = ""
        for d in decision.get("details", []):
            if isinstance(d, dict):
                d_zh = html.escape(str(d.get("zh", "")))
                d_en = html.escape(str(d.get("en", "")))
                details_html += f"""
                <li>
                    <span class="zh">{d_zh}</span>
                    <span class="en">{d_en}</span>
                </li>
                """
            else:
                details_html += f"<li>{html.escape(str(d))}</li>"

        source_files_str = html.escape(", ".join(f.name for f in self.source_files) if self.source_files else "None")
        now_str = html.escape(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        traces = self.get_trace_snapshots()
        traces_html = ""
        if traces:
            traces_items = "".join(f"<li><code>{html.escape(t.name)}</code></li>" for t in traces[:5])
            more_str = (
                f"<p style='color:#94a3b8;font-size:13px;'>... and {len(traces) - 5} more snapshot(s) in <code>{html.escape(str(self.trace_dir))}</code></p>"
                if len(traces) > 5
                else ""
            )
            traces_html = f"""
  <div class="card">
    <h2 style="margin-top:0; font-size:18px;">
      <span class="zh">路由诊断快照 ({len(traces)} 份)</span>
      <span class="en">Captured Traceroute Snapshots ({len(traces)})</span>
    </h2>
    <ul style="font-family:monospace; font-size:13px; color:#38bdf8;">
      {traces_items}
    </ul>
    {more_str}
  </div>
"""

        html_content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>米哈游国服网络连通性诊断报告 | miHoYo CN Diagnostics</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Microsoft YaHei", sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 30px; }}
  body.lang-zh .en {{ display: none !important; }}
  body.lang-en .zh {{ display: none !important; }}
  .container {{ max-width: 1000px; margin: 0 auto; }}
  .header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }}
  h1 {{ margin: 0; font-size: 24px; color: #38bdf8; }}
  .lang-switch {{ display: flex; gap: 4px; background: #1e293b; padding: 4px; border-radius: 8px; border: 1px solid #334155; }}
  .lang-btn {{ background: transparent; border: none; color: #94a3b8; padding: 5px 14px; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 600; transition: all 0.2s; }}
  .lang-btn.active {{ background: #38bdf8; color: #0f172a; }}
  .meta {{ color: #94a3b8; font-size: 14px; margin-bottom: 24px; }}
  .card {{ background: #1e293b; border-radius: 12px; padding: 24px; margin-bottom: 24px; border: 1px solid #334155; }}
  .badge {{ display: inline-block; padding: 6px 14px; border-radius: 9999px; font-weight: 700; font-size: 14px; background: {badge_color}; color: #ffffff; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
  th, td {{ text-align: left; padding: 12px 14px; border-bottom: 1px solid #334155; }}
  th {{ background: #0f172a; color: #94a3b8; font-size: 13px; text-transform: uppercase; letter-spacing: 0.05em; }}
  ul {{ padding-left: 20px; line-height: 1.7; color: #cbd5e1; }}
  li {{ margin-bottom: 6px; }}
  .action-box {{ background: #0f172a; border-left: 4px solid #38bdf8; padding: 14px 18px; border-radius: 6px; margin-top: 16px; font-size: 15px; }}
</style>
<script>
  function setLang(lang) {{
    document.body.className = 'lang-' + lang;
    document.documentElement.lang = (lang === 'zh') ? 'zh-CN' : 'en-US';
    document.querySelectorAll('.lang-btn').forEach(function(b) {{ b.classList.remove('active'); }});
    var activeBtn = document.getElementById('btn-' + lang);
    if (activeBtn) activeBtn.classList.add('active');
    try {{ localStorage.setItem('mihoyo_diag_lang', lang); }} catch (e) {{}}
  }}
  window.addEventListener('DOMContentLoaded', function() {{
    var saved = 'zh';
    try {{ saved = localStorage.getItem('mihoyo_diag_lang') || 'zh'; }} catch (e) {{}}
    setLang(saved);
  }});
</script>
</head>
<body class="lang-zh">
<div class="container">
  <div class="header">
    <h1>
      <span class="zh">米哈游国服网络连通性诊断报告</span>
      <span class="en">miHoYo China Connectivity Diagnostic Report</span>
    </h1>
    <div class="lang-switch">
      <button id="btn-zh" class="lang-btn active" onclick="setLang('zh')">简体中文</button>
      <button id="btn-en" class="lang-btn" onclick="setLang('en')">English</button>
    </div>
  </div>

  <div class="meta">
    <span class="zh">生成时间: <strong>{now_str} (本地时间)</strong> | 数据源: <strong>{source_files_str}</strong> | 样本数: <strong>{len(self.records)}</strong></span>
    <span class="en">Generated on: <strong>{now_str} (Local Time)</strong> | Source: <strong>{source_files_str}</strong> | Total Samples: <strong>{len(self.records)}</strong></span>
  </div>

  <div class="card">
    <div style="display:flex; justify-content:space-between; align-items:center;">
      <h2 style="margin:0; font-size:18px;">
        <span class="zh">加速器选购评估结论</span>
        <span class="en">Buying Recommendation</span>
      </h2>
      <span class="badge">
        <span class="zh">{badge_zh}</span>
        <span class="en">{badge_en}</span>
      </span>
    </div>
    <p style="font-size:16px; margin: 16px 0 8px 0;">
      <strong>
        <span class="zh">{summary_zh}</span>
        <span class="en">{summary_en}</span>
      </strong>
    </p>
    <ul>{details_html}</ul>
    <div class="action-box">
      <strong><span class="zh">建议操作: </span><span class="en">Recommended Action: </span></strong>
      <span class="zh">{action_zh}</span>
      <span class="en">{action_en}</span>
    </div>
  </div>

  <div class="card">
    <h2 style="margin-top:0; font-size:18px;">
      <span class="zh">目标节点性能指标</span>
      <span class="en">Target Performance Metrics</span>
    </h2>
    <table>
      <thead>
        <tr>
          <th><span class="zh">监测目标</span><span class="en">Target</span></th>
          <th><span class="zh">丢包率</span><span class="en">Loss %</span></th>
          <th><span class="zh">平均时延</span><span class="en">Avg RTT</span></th>
          <th><span class="zh">抖动</span><span class="en">Jitter</span></th>
          <th><span class="zh">TCP 握手</span><span class="en">TCP 443</span></th>
          <th><span class="zh">晚高峰丢包 (19:00-23:00)</span><span class="en">CST Peak Loss (19:00-23:00)</span></th>
          <th><span class="zh">非高峰丢包</span><span class="en">Off-Peak Loss</span></th>
        </tr>
      </thead>
      <tbody>
        {rows_html}
      </tbody>
    </table>
  </div>
{traces_html}
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
