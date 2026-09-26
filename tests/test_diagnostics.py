"""
Unit test suite for miHoYo connectivity diagnostics.
Tests multi-language ping regex parsing, async TCP handshakes,
decision matrix logic, table formatting, and CSV serialization.
"""

import asyncio
import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from analyze import ConnectivityAnalyzer, cjk_display_width, cjk_ljust, find_log_files
from find_game_ip import add_endpoint_to_config, format_table
from game_discovery import (
    DEFAULT_TRACKED_GAMES,
    get_target_executable_map,
    load_tracked_games,
)
from monitor import (
    CSV_HEADERS,
    NetworkMonitor,
    ping_target,
    test_tcp_handshake,
)


class TestPingParsing(unittest.IsolatedAsyncioTestCase):
    async def test_english_ping_parsing(self):
        sample_en = (
            "Pinging 1.1.1.1 with 32 bytes of data:\n"
            "Reply from 1.1.1.1: bytes=32 time=14ms TTL=57\n"
            "Reply from 1.1.1.1: bytes=32 time=16ms TTL=57\n"
            "\n"
            "Ping statistics for 1.1.1.1:\n"
            "    Packets: Sent = 2, Received = 2, Lost = 0 (0% loss),\n"
            "Approximate round trip times in milli-seconds:\n"
            "    Minimum = 14ms, Maximum = 16ms, Average = 15ms\n"
        )
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            proc = AsyncMock()
            proc.communicate.return_value = (sample_en.encode("utf-8"), b"")
            mock_exec.return_value = proc

            res = await ping_target("1.1.1.1", burst_count=2, timeout_ms=1000)
            self.assertEqual(res["sent"], 2)
            self.assertEqual(res["recv"], 2)
            self.assertEqual(res["loss_pct"], 0.0)
            self.assertEqual(res["min_rtt"], 14.0)
            self.assertEqual(res["max_rtt"], 16.0)
            self.assertEqual(res["avg_rtt"], 15.0)
            self.assertEqual(res["jitter"], 2.0)

    async def test_simplified_chinese_ping_parsing(self):
        sample_zh = (
            "正在 Ping 203.107.36.87 具有 32 字节的数据:\n"
            "来自 203.107.36.87 的回复: 字节=32 时间=238ms TTL=115\n"
            "来自 203.107.36.87 的回复: 字节=32 时间=240ms TTL=115\n"
            "\n"
            "203.107.36.87 的 Ping 统计信息:\n"
            "    数据包: 已发送 = 2，已接收 = 2，丢失 = 0 (0% 丢失)，\n"
            "往返行程的估计时间(以毫秒为单位):\n"
            "    最短 = 238ms，最长 = 240ms，平均 = 239ms\n"
        )
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            proc = AsyncMock()
            proc.communicate.return_value = (sample_zh.encode("gbk", errors="ignore"), b"")
            mock_exec.return_value = proc

            res = await ping_target("203.107.36.87", burst_count=2, timeout_ms=1000)
            self.assertEqual(res["sent"], 2)
            self.assertEqual(res["recv"], 2)
            self.assertEqual(res["loss_pct"], 0.0)
            self.assertEqual(res["min_rtt"], 238.0)
            self.assertEqual(res["max_rtt"], 240.0)
            self.assertEqual(res["avg_rtt"], 239.0)
            self.assertEqual(res["jitter"], 2.0)

    async def test_traditional_chinese_ping_parsing(self):
        sample_tw = (
            "正在 Ping 122.156.129.54 具有 32 位元組的資料:\n"
            "來自 122.156.129.54 的回覆: 位元組=32 時間=255ms TTL=49\n"
            "來自 122.156.129.54 的回覆: 位元組=32 時間<1ms TTL=49\n"
            "\n"
            "122.156.129.54 的 Ping 統計資料:\n"
            "    封包: 已傳送 = 2，已收到 = 2，已遺失 = 0 (0% 遺失)，\n"
            "大約的來回時間 (毫秒):\n"
            "    最小值 = 1ms，最大值 = 255ms，平均 = 128ms\n"
        )
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            proc = AsyncMock()
            proc.communicate.return_value = (sample_tw.encode("utf-8"), b"")
            mock_exec.return_value = proc

            res = await ping_target("122.156.129.54", burst_count=2, timeout_ms=1000)
            self.assertEqual(res["sent"], 2)
            self.assertEqual(res["recv"], 2)
            self.assertEqual(res["loss_pct"], 0.0)
            self.assertEqual(res["min_rtt"], 1.0)
            self.assertEqual(res["max_rtt"], 255.0)


class TestTcpHandshake(unittest.IsolatedAsyncioTestCase):
    async def test_invalid_port(self):
        ok, rtt = await test_tcp_handshake("127.0.0.1", port=0, timeout_ms=500)
        self.assertFalse(ok)
        self.assertEqual(rtt, -1.0)

    async def test_closed_port_failure(self):
        # Port 1 is rarely open on localhost
        ok, rtt = await test_tcp_handshake("127.0.0.1", port=1, timeout_ms=200)
        self.assertFalse(ok)
        self.assertEqual(rtt, -1.0)


class TestCjkFormatting(unittest.TestCase):
    def test_cjk_width(self):
        self.assertEqual(cjk_display_width("abc"), 3)
        self.assertEqual(cjk_display_width("原神"), 4)
        self.assertEqual(cjk_display_width("原神CN"), 6)

    def test_cjk_ljust(self):
        padded = cjk_ljust("原神", 10)
        self.assertEqual(cjk_display_width(padded), 10)

    def test_format_table(self):
        headers = ["Game", "Latency"]
        rows = [["原神", "15ms"], ["StarRail", "20ms"]]
        table = format_table(headers, rows)
        self.assertIn("原神", table)
        self.assertIn("StarRail", table)


class TestConfigAndDiscovery(unittest.TestCase):
    def test_default_tracked_games(self):
        mapping = get_target_executable_map(DEFAULT_TRACKED_GAMES)
        self.assertIn("yuanshen.exe", mapping)
        self.assertIn("starrail.exe", mapping)
        self.assertIn("zenlesszonezero.exe", mapping)
        self.assertIn("bh3.exe", mapping)

    def test_add_endpoint_dedup(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / "config.json"
            cfg_path.write_text(json.dumps({"targets": {"mihoyo_endpoints": []}}), encoding="utf-8")

            # Add first time -> True
            self.assertTrue(add_endpoint_to_config("Node-1", "1.2.3.4", 443, cfg_path))
            # Add duplicate host and port -> False
            self.assertFalse(add_endpoint_to_config("Node-Dup", "1.2.3.4", 443, cfg_path))
            # Add same host with different port -> True
            self.assertTrue(add_endpoint_to_config("Node-Port2", "1.2.3.4", 80, cfg_path))


class TestDecisionMatrix(unittest.TestCase):
    def _create_sample_csv(self, tmpdir: str, rows: list[dict]):
        csv_file = Path(tmpdir) / "connectivity_test.csv"
        with open(csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
            writer.writeheader()
            for r in rows:
                writer.writerow(r)
        return csv_file

    def test_local_fault_verdict(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rows = [
                {
                    "timestamp_local": f"2026-09-26 12:00:0{i}",
                    "timestamp_cst": f"2026-09-27 00:00:0{i}",
                    "cst_hour": 0,
                    "is_cst_peak": False,
                    "active_game": "None",
                    "target_name": "Local-Gateway",
                    "target_host": "192.168.1.1",
                    "target_type": "control_local",
                    "packets_sent": 5,
                    "packets_recv": 4,
                    "loss_pct": 20.0,
                    "min_rtt_ms": 1.0,
                    "avg_rtt_ms": 1.0,
                    "max_rtt_ms": 2.0,
                    "jitter_ms": 1.0,
                    "tcp_port": 0,
                    "tcp_success": False,
                    "tcp_handshake_ms": -1.0,
                    "anomaly_triggered": False,
                }
                for i in range(6)
            ]
            # Add a miHoYo target
            for i in range(6):
                rows.append({
                    "timestamp_local": f"2026-09-26 12:00:0{i}",
                    "timestamp_cst": f"2026-09-27 00:00:0{i}",
                    "cst_hour": 0,
                    "is_cst_peak": False,
                    "active_game": "None",
                    "target_name": "Aliyun-AntiDDoS-1",
                    "target_host": "203.107.36.87",
                    "target_type": "mihoyo_edge",
                    "packets_sent": 5,
                    "packets_recv": 5,
                    "loss_pct": 0.0,
                    "min_rtt_ms": 230.0,
                    "avg_rtt_ms": 235.0,
                    "max_rtt_ms": 240.0,
                    "jitter_ms": 10.0,
                    "tcp_port": 443,
                    "tcp_success": True,
                    "tcp_handshake_ms": 235.0,
                    "anomaly_triggered": False,
                })
            csv_path = self._create_sample_csv(tmpdir, rows)
            analyzer = ConnectivityAnalyzer(log_path=str(csv_path), trace_dir=tmpdir)
            decision = analyzer.evaluate_decision_matrix()
            self.assertEqual(decision["verdict"], "DO_NOT_BUY_LOCAL_FAULT")

    def test_stable_high_rtt_verdict(self):
        """North America East Coast players with ~265ms RTT and 0% loss should NOT be told mild packet loss."""
        with tempfile.TemporaryDirectory() as tmpdir:
            rows = []
            for i in range(6):
                rows.append({
                    "timestamp_local": f"2026-09-26 12:00:0{i}",
                    "timestamp_cst": f"2026-09-27 00:00:0{i}",
                    "cst_hour": 0,
                    "is_cst_peak": False,
                    "active_game": "None",
                    "target_name": "Local-Gateway",
                    "target_host": "192.168.1.1",
                    "target_type": "control_local",
                    "packets_sent": 5,
                    "packets_recv": 5,
                    "loss_pct": 0.0,
                    "min_rtt_ms": 1.0,
                    "avg_rtt_ms": 1.0,
                    "max_rtt_ms": 1.0,
                    "jitter_ms": 0.0,
                    "tcp_port": 0,
                    "tcp_success": False,
                    "tcp_handshake_ms": -1.0,
                    "anomaly_triggered": False,
                })
                rows.append({
                    "timestamp_local": f"2026-09-26 12:00:0{i}",
                    "timestamp_cst": f"2026-09-27 00:00:0{i}",
                    "cst_hour": 0,
                    "is_cst_peak": False,
                    "active_game": "None",
                    "target_name": "Global-Cloudflare",
                    "target_host": "1.1.1.1",
                    "target_type": "control_global",
                    "packets_sent": 5,
                    "packets_recv": 5,
                    "loss_pct": 0.0,
                    "min_rtt_ms": 3.0,
                    "avg_rtt_ms": 3.0,
                    "max_rtt_ms": 3.0,
                    "jitter_ms": 0.0,
                    "tcp_port": 53,
                    "tcp_success": True,
                    "tcp_handshake_ms": 4.0,
                    "anomaly_triggered": False,
                })
                rows.append({
                    "timestamp_local": f"2026-09-26 12:00:0{i}",
                    "timestamp_cst": f"2026-09-27 00:00:0{i}",
                    "cst_hour": 0,
                    "is_cst_peak": False,
                    "active_game": "None",
                    "target_name": "Aliyun-AntiDDoS-1",
                    "target_host": "203.107.36.87",
                    "target_type": "mihoyo_edge",
                    "packets_sent": 5,
                    "packets_recv": 5,
                    "loss_pct": 0.0,
                    "min_rtt_ms": 265.0,
                    "avg_rtt_ms": 270.0,
                    "max_rtt_ms": 275.0,
                    "jitter_ms": 10.0,
                    "tcp_port": 443,
                    "tcp_success": True,
                    "tcp_handshake_ms": 270.0,
                    "anomaly_triggered": False,
                })
            csv_path = self._create_sample_csv(tmpdir, rows)
            analyzer = ConnectivityAnalyzer(log_path=str(csv_path), trace_dir=tmpdir)
            decision = analyzer.evaluate_decision_matrix()
            self.assertEqual(decision["verdict"], "DO_NOT_BUY_HIGH_RTT_STABLE")
            self.assertNotIn("0.0% loss detected", decision["summary_en"])

    def test_html_report_escaping(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rows = []
            for i in range(6):
                rows.append({
                    "timestamp_local": f"2026-09-26 12:00:0{i}",
                    "timestamp_cst": f"2026-09-27 00:00:0{i}",
                    "cst_hour": 0,
                    "is_cst_peak": False,
                    "active_game": "None",
                    "target_name": "<script>alert(1)</script>",
                    "target_host": "203.107.36.87",
                    "target_type": "mihoyo_edge",
                    "packets_sent": 5,
                    "packets_recv": 5,
                    "loss_pct": 0.0,
                    "min_rtt_ms": 100.0,
                    "avg_rtt_ms": 100.0,
                    "max_rtt_ms": 100.0,
                    "jitter_ms": 0.0,
                    "tcp_port": 443,
                    "tcp_success": True,
                    "tcp_handshake_ms": 100.0,
                    "anomaly_triggered": False,
                })
            csv_path = self._create_sample_csv(tmpdir, rows)
            analyzer = ConnectivityAnalyzer(log_path=str(csv_path), trace_dir=tmpdir)
            out_html, _ = analyzer.generate_html_report(output_path=str(Path(tmpdir) / "report.html"))
            content = out_html.read_text(encoding="utf-8")
            self.assertNotIn("<script>alert(1)</script>", content)
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", content)

    def test_legacy_udp_rows_ignored_in_decision_matrix(self):
        """Historical 100% loss UDP rows must not trigger false BUY_ACCELERATOR."""
        with tempfile.TemporaryDirectory() as tmpdir:
            rows = []
            for i in range(6):
                # Clean local gateway
                rows.append({
                    "timestamp_local": f"2026-09-26 12:00:0{i}",
                    "timestamp_cst": f"2026-09-27 00:00:0{i}",
                    "cst_hour": 0,
                    "is_cst_peak": False,
                    "active_game": "None",
                    "target_name": "Local-Gateway",
                    "target_host": "192.168.1.1",
                    "target_type": "control_local",
                    "packets_sent": 5,
                    "packets_recv": 5,
                    "loss_pct": 0.0,
                    "min_rtt_ms": 1.0,
                    "avg_rtt_ms": 1.0,
                    "max_rtt_ms": 1.0,
                    "jitter_ms": 0.0,
                    "tcp_port": 0,
                    "tcp_success": False,
                    "tcp_handshake_ms": -1.0,
                    "anomaly_triggered": False,
                })
                # Clean edge node
                rows.append({
                    "timestamp_local": f"2026-09-26 12:00:0{i}",
                    "timestamp_cst": f"2026-09-27 00:00:0{i}",
                    "cst_hour": 0,
                    "is_cst_peak": False,
                    "active_game": "None",
                    "target_name": "Aliyun-AntiDDoS-1",
                    "target_host": "203.107.36.87",
                    "target_type": "mihoyo_edge",
                    "packets_sent": 5,
                    "packets_recv": 5,
                    "loss_pct": 0.0,
                    "min_rtt_ms": 200.0,
                    "avg_rtt_ms": 205.0,
                    "max_rtt_ms": 210.0,
                    "jitter_ms": 5.0,
                    "tcp_port": 443,
                    "tcp_success": True,
                    "tcp_handshake_ms": 205.0,
                    "anomaly_triggered": False,
                })
                # Legacy UDP game combat server that dropped ICMP pings
                rows.append({
                    "timestamp_local": f"2026-09-26 12:00:0{i}",
                    "timestamp_cst": f"2026-09-27 00:00:0{i}",
                    "cst_hour": 0,
                    "is_cst_peak": False,
                    "active_game": "原神",
                    "target_name": "LiveGame-原神-UDP",
                    "target_host": "47.116.110.53",
                    "target_type": "mihoyo_live_game",
                    "packets_sent": 5,
                    "packets_recv": 0,
                    "loss_pct": 100.0,
                    "min_rtt_ms": -1.0,
                    "avg_rtt_ms": -1.0,
                    "max_rtt_ms": -1.0,
                    "jitter_ms": -1.0,
                    "tcp_port": 0,
                    "tcp_success": False,
                    "tcp_handshake_ms": -1.0,
                    "anomaly_triggered": False,
                })

            csv_path = self._create_sample_csv(tmpdir, rows)
            analyzer = ConnectivityAnalyzer(log_path=str(csv_path), trace_dir=tmpdir)
            decision = analyzer.evaluate_decision_matrix()
            # Must remain DO_NOT_BUY_EXCELLENT_CONNECTION because the 100% loss UDP is ignored
            self.assertEqual(decision["verdict"], "DO_NOT_BUY_EXCELLENT_CONNECTION")


class TestMonitorTargetFiltering(unittest.TestCase):
    def test_resolve_targets_filters_udp(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / "config.json"
            cfg_path.write_text(json.dumps({
                "targets": {
                    "local_gateway": "192.168.1.1",
                    "global_control": "1.1.1.1",
                    "asia_transit_control": "20.210.150.1",
                    "mihoyo_endpoints": []
                },
                "paths": {"log_file_template": str(Path(tmpdir) / "test.csv")}
            }), encoding="utf-8")

            monitor = NetworkMonitor(config_path=str(cfg_path))
            running_games = [{"game_name": "原神 (Genshin Impact CN)", "exe_name": "YuanShen.exe", "pid": 1234}]
            conns = [
                {"game_name": "原神", "protocol": "TCP", "remote_ip": "106.15.239.171", "remote_port": 443},
                {"game_name": "原神", "protocol": "UDP", "remote_ip": "47.116.110.53", "remote_port": 22101},
            ]

            targets = monitor.resolve_targets(running_games=running_games, game_connections=conns)
            target_names = [t["name"] for t in targets]

            # TCP socket must be added
            self.assertIn("LiveGame-原神-TCP", target_names)
            # UDP socket must be excluded
            self.assertNotIn("LiveGame-原神-UDP", target_names)
            self.assertFalse(any("UDP" in name for name in target_names))


if __name__ == "__main__":
    unittest.main()
