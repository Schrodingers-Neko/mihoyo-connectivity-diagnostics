"""
Dynamic Game Discovery and Process/Socket Inspector for miHoYo Games.
Scans the miHoYo Launcher directory, discovers installed games, identifies
running processes, and inspects live game server network sockets.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

DEFAULT_LAUNCHER_GAMES_DIR = r"D:\Program Files\miHoYo Launcher\games"

# Patterns of auxiliary / non-game executables to ignore
IGNORED_EXE_PATTERNS = [
    r"crash",
    r"plugin",
    r"refresher",
    r"update",
    r"uninstall",
    r"helper",
    r"reporter",
    r"cefview",
    r"zfgamebrowser",
]


def load_launcher_dir(config_path: Path | str = "config.json") -> Path:
    """Read launcher_games_dir from config.json if available."""
    config_file = Path(config_path)
    if config_file.is_file():
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                custom_dir = data.get("launcher_games_dir")
                if custom_dir and os.path.isdir(custom_dir):
                    return Path(custom_dir)
        except Exception:
            pass
    return Path(DEFAULT_LAUNCHER_GAMES_DIR)


def is_auxiliary_exe(exe_name: str, rel_path: str) -> bool:
    """Check if an executable is an auxiliary crash/updater/plugin executable."""
    lower_name = exe_name.lower()
    lower_path = rel_path.lower()
    for pattern in IGNORED_EXE_PATTERNS:
        if re.search(pattern, lower_name) or re.search(pattern, lower_path):
            return True
    return False


def discover_installed_games(launcher_dir: Path | str | None = None) -> list[dict[str, Any]]:
    """
    Scan launcher directory for game subdirectories and discover main game executables.
    Returns a list of discovered games:
    [
        {
            "game_name": "Genshin Impact Game",
            "folder": "D:\\...\\Genshin Impact Game",
            "exe_name": "YuanShen.exe",
            "exe_path": "D:\\...\\YuanShen.exe"
        },
        ...
    ]
    """
    if launcher_dir is None:
        launcher_dir = load_launcher_dir()
    else:
        launcher_dir = Path(launcher_dir)

    discovered = []
    if not launcher_dir.is_dir():
        return discovered

    for game_folder in launcher_dir.iterdir():
        if not game_folder.is_dir():
            continue

        # Look for executables in the root of the game folder first
        candidates = []
        for file in game_folder.iterdir():
            if file.is_file() and file.suffix.lower() == ".exe":
                rel = file.name
                if not is_auxiliary_exe(file.name, rel):
                    candidates.append(file)

        # If none found directly in root, check 1 level down
        if not candidates:
            for sub_file in game_folder.glob("*/*.exe"):
                rel = str(sub_file.relative_to(game_folder))
                if not is_auxiliary_exe(sub_file.name, rel):
                    candidates.append(sub_file)

        # Prefer larger executables or game-like names if multiple candidates exist
        if candidates:
            candidates.sort(key=lambda p: p.stat().st_size, reverse=True)
            primary_exe = candidates[0]
            discovered.append({
                "game_name": game_folder.name,
                "folder": str(game_folder),
                "exe_name": primary_exe.name,
                "exe_path": str(primary_exe),
            })

    return discovered


def get_running_games(discovered_games: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """
    Query active Windows processes to check if any discovered miHoYo games are running.
    Returns:
    [
        {
            "game_name": "Genshin Impact Game",
            "exe_name": "YuanShen.exe",
            "pid": 11620
        },
        ...
    ]
    """
    if discovered_games is None:
        discovered_games = discover_installed_games()

    if not discovered_games:
        return []

    target_exes = {g["exe_name"].lower(): g for g in discovered_games}

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
            if lower_name in target_exes:
                try:
                    pid = int(pid_str)
                    game_info = target_exes[lower_name]
                    running.append({
                        "game_name": game_info["game_name"],
                        "exe_name": game_info["exe_name"],
                        "pid": pid,
                    })
                except ValueError:
                    continue

    return running


def get_game_connections(running_games: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Query netstat to find active TCP and UDP sockets for running game PIDs.
    Returns active remote IPs and ports.
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
                        connections.append({
                            "game_name": pids_to_game[pid]["game_name"],
                            "exe_name": pids_to_game[pid]["exe_name"],
                            "pid": pid,
                            "protocol": "TCP",
                            "local": local,
                            "remote_ip": r_ip,
                            "remote_port": int(r_port) if r_port.isdigit() else 0,
                            "state": state,
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
                        connections.append({
                            "game_name": pids_to_game[pid]["game_name"],
                            "exe_name": pids_to_game[pid]["exe_name"],
                            "pid": pid,
                            "protocol": "UDP",
                            "local": local,
                            "remote_ip": r_ip,
                            "remote_port": int(r_port) if r_port.isdigit() else 0,
                            "state": "ACTIVE",
                        })

    return connections


if __name__ == "__main__":
    print("=== miHoYo Game Discovery Test ===")
    games = discover_installed_games()
    print(f"Discovered {len(games)} installed games:")
    for g in games:
        print(f" - [{g['game_name']}] Exe: {g['exe_name']} at {g['exe_path']}")

    running = get_running_games(games)
    print(f"\nRunning game processes ({len(running)}):")
    for r in running:
        print(f" - [{r['game_name']}] PID: {r['pid']} ({r['exe_name']})")

    conns = get_game_connections(running)
    print(f"\nActive Game Connections ({len(conns)}):")
    for c in conns:
        print(f" - {c['protocol']} {c['remote_ip']}:{c['remote_port']} [{c['state']}] ({c['game_name']})")
