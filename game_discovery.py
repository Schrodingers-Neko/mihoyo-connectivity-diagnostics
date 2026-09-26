"""
miHoYo China Server (国服) Game Process and Socket Discovery.
Inspects running Windows processes against a user-configurable registry of
China-server-exclusive miHoYo game executables (YuanShen.exe, StarRail.exe,
ZenlessZoneZero.exe, BH3.exe), completely independent of installation drive or folder paths.
"""

from __future__ import annotations

import csv
import io
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Default registry of miHoYo China Server (国服) game executables.
# Global server client executables (e.g. GenshinImpact.exe, Honkai Impact 3rd.exe) are excluded.
DEFAULT_TRACKED_GAMES: list[dict[str, Any]] = [
    {
        "name": "原神 (Genshin Impact CN)",
        "executables": ["YuanShen.exe"],
        "server_ports": [22101, 22102],
    },
    {
        "name": "崩坏：星穹铁道 (Honkai: Star Rail CN)",
        "executables": ["StarRail.exe"],
        "server_ports": [],
    },
    {
        "name": "绝区零 (Zenless Zone Zero CN)",
        "executables": ["ZenlessZoneZero.exe"],
        "server_ports": [],
    },
    {
        "name": "崩坏3 (Honkai Impact 3rd CN)",
        "executables": ["BH3.exe"],
        "server_ports": [],
    },
]


def load_tracked_games(config_path: Path | str = "config.json") -> list[dict[str, Any]]:
    """Read tracked_games from config.json or return default CN registry."""
    config_file = Path(config_path)
    if config_file.is_file():
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                custom_games = data.get("tracked_games")
                if custom_games and isinstance(custom_games, list):
                    return custom_games
        except Exception:
            pass
    return DEFAULT_TRACKED_GAMES


def get_target_executable_map(
    tracked_games: list[dict[str, Any]] | None = None,
) -> dict[str, dict[str, Any]]:
    """
    Build a case-insensitive lookup map: { "yuanshen.exe": game_dict, ... }
    """
    if tracked_games is None:
        tracked_games = load_tracked_games()

    mapping = {}
    for g in tracked_games:
        for exe in g.get("executables", []):
            mapping[exe.lower()] = g
    return mapping


def get_running_games(
    config_path: Path | str = "config.json",
    tracked_games: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """
    Scan active Windows processes for configured miHoYo China game executables.
    Drive-independent: matches against process names regardless of install path.
    Returns:
    [
        {
            "game_name": "原神 (Genshin Impact CN)",
            "exe_name": "YuanShen.exe",
            "pid": 11620
        },
        ...
    ]
    """
    exe_map = get_target_executable_map(tracked_games or load_tracked_games(config_path))
    if not exe_map:
        return []

    try:
        output = subprocess.check_output(
            ["tasklist", "/FO", "CSV", "/NH"],
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
    except Exception:
        return []

    running = []
    reader = csv.reader(io.StringIO(output))
    for row in reader:
        if len(row) >= 2:
            image_name = row[0].strip()
            pid_str = row[1].strip()
            lower_name = image_name.lower()
            if lower_name in exe_map:
                try:
                    pid = int(pid_str)
                    game_info = exe_map[lower_name]
                    running.append({
                        "game_name": game_info["name"],
                        "exe_name": image_name,
                        "pid": pid,
                    })
                except ValueError:
                    continue

    return running


def get_game_connections(running_games: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Query netstat to find active TCP and UDP sockets for running game PIDs.
    Returns active remote IPs and ports with descriptive China-server labels.
    """
    if not running_games:
        return []

    pids_to_game = {g["pid"]: g for g in running_games}
    pid_set = set(pids_to_game.keys())

    try:
        output = subprocess.check_output(
            ["netstat", "-ano"],
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
    except Exception:
        return []

    connections = []
    for line in output.splitlines():
        parts = line.split()
        if not parts:
            continue

        proto = parts[0].upper()
        # TCP format: Proto LocalAddress ForeignAddress State PID
        # UDP format: Proto LocalAddress ForeignAddress [State if any] PID
        if proto == "TCP" and len(parts) >= 5:
            try:
                pid = int(parts[-1])
            except ValueError:
                continue

            if pid in pid_set:
                local = parts[1]
                foreign = parts[2]
                state = parts[3]
                if ":" in foreign:
                    r_ip, r_port = foreign.rsplit(":", 1)
                    if r_ip not in ("127.0.0.1", "0.0.0.0", "*", "[::]"):
                        port_int = int(r_port) if r_port.isdigit() else 0
                        game = pids_to_game[pid]
                        desc = _classify_connection(game["exe_name"], proto, port_int)
                        connections.append({
                            "game_name": game["game_name"],
                            "exe_name": game["exe_name"],
                            "pid": pid,
                            "protocol": "TCP",
                            "local": local,
                            "remote_ip": r_ip,
                            "remote_port": port_int,
                            "state": state,
                            "description": desc,
                        })

        elif proto == "UDP" and len(parts) >= 4:
            try:
                pid = int(parts[-1])
            except ValueError:
                continue

            if pid in pid_set:
                local = parts[1]
                foreign = parts[2]
                if ":" in foreign:
                    r_ip, r_port = foreign.rsplit(":", 1)
                    if r_ip not in ("127.0.0.1", "0.0.0.0", "*", "[::]"):
                        port_int = int(r_port) if r_port.isdigit() else 0
                        game = pids_to_game[pid]
                        desc = _classify_connection(game["exe_name"], proto, port_int)
                        connections.append({
                            "game_name": game["game_name"],
                            "exe_name": game["exe_name"],
                            "pid": pid,
                            "protocol": "UDP",
                            "local": local,
                            "remote_ip": r_ip,
                            "remote_port": port_int,
                            "state": "ACTIVE",
                            "description": desc,
                        })

    return connections


def _classify_connection(exe_name: str, proto: str, remote_port: int) -> str:
    """Classify the role of the connection based on executable and port."""
    lower_exe = exe_name.lower()

    if "yuanshen" in lower_exe:
        if proto == "UDP" and remote_port in (22101, 22102):
            return "原神 KCP 战斗服务器 (Genshin KCP Combat Server)"
        elif remote_port in (8999, 443, 80):
            return "原神 调度/网关节点 (Genshin Dispatch/Gateway)"
        return "原神 通信节点 (Genshin Node)"

    if "starrail" in lower_exe:
        if remote_port in (443, 80):
            return "星穹铁道 网关/调度服务 (HSR Gateway/Dispatch)"
        return "星穹铁道 游戏通信节点 (HSR Game Server Node)"

    if "zenless" in lower_exe:
        if remote_port in (443, 80):
            return "绝区零 网关/调度服务 (ZZZ Gateway/Dispatch)"
        return "绝区零 游戏通信节点 (ZZZ Game Server Node)"

    if "bh3" in lower_exe:
        return "崩坏3 游戏/服务节点 (HI3 Node)"

    return "miHoYo 游戏服务节点 (miHoYo Game Node)"


# Auxiliary optional disk scanner helper (if user wants to locate physical folders)
def discover_installed_games(scan_dir: Path | str | None = None) -> list[dict[str, Any]]:
    """Optional helper: scans directory for game folders matching tracked games."""
    if scan_dir is None:
        return []
    target_path = Path(scan_dir)
    if not target_path.is_dir():
        return []

    tracked = load_tracked_games()
    all_exes = set()
    for g in tracked:
        for e in g.get("executables", []):
            all_exes.add(e.lower())

    discovered = []
    for item in target_path.iterdir():
        if item.is_dir():
            for f in item.glob("*.exe"):
                if f.name.lower() in all_exes:
                    discovered.append({
                        "game_name": item.name,
                        "folder": str(item),
                        "exe_name": f.name,
                        "exe_path": str(f),
                    })
    return discovered


if __name__ == "__main__":
    print("=== miHoYo China Server (国服) Game Process Discovery ===")
    tracked = load_tracked_games()
    print(f"Tracked CN Game Profiles ({len(tracked)}):")
    for t in tracked:
        exes = ", ".join(t.get("executables", []))
        print(f"  * [{t['name']}] Exe: {exes}")

    running = get_running_games()
    print(f"\nRunning miHoYo Game Processes ({len(running)}):")
    for r in running:
        print(f"  * [{r['game_name']}] PID: {r['pid']} ({r['exe_name']})")

    conns = get_game_connections(running)
    print(f"\nActive Game Connections ({len(conns)}):")
    for c in conns:
        print(f"  * {c['protocol']} {c['remote_ip']}:{c['remote_port']} [{c['state']}] - {c['description']}")
