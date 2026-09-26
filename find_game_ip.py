"""
CLI tool to inspect active miHoYo game connections in real-time
and optionally add active game server endpoints into config.json.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from game_discovery import (
    discover_installed_games,
    get_game_connections,
    get_running_games,
    load_launcher_dir,
)


if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def format_table(headers: list[str], rows: list[list[str]]) -> str:
    """Format a clean plain-text table."""
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))

    header_line = " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    sep_line = "-+-".join("-" * col_widths[i] for i in range(len(headers)))
    row_lines = [
        " | ".join(str(cell).ljust(col_widths[i]) for i, cell in enumerate(row))
        for row in rows
    ]
    return f"{header_line}\n{sep_line}\n" + "\n".join(row_lines)


def add_endpoint_to_config(
    name: str,
    host: str,
    port: int,
    config_path: Path | str = "config.json",
) -> bool:
    """Append a new endpoint into config.json targets.mihoyo_endpoints."""
    cfg_file = Path(config_path)
    if not cfg_file.is_file():
        print(f"Error: {config_path} not found.")
        return False

    with open(cfg_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    endpoints = data.setdefault("targets", {}).setdefault("mihoyo_endpoints", [])
    for ep in endpoints:
        if ep.get("host") == host:
            print(f"Endpoint {host} already exists in {config_path} as '{ep.get('name')}'.")
            return False

    endpoints.append({"name": name, "host": host, "port": port})
    with open(cfg_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    print(f"Successfully added [{name}] {host}:{port} into {config_path}.")
    return True


def display_status(discovered: list[dict[str, Any]], config_path: str = "config.json") -> list[dict[str, Any]]:
    running = get_running_games(discovered)
    connections = get_game_connections(running)

    print("\n" + "=" * 65)
    print(" miHoYo Active Game Connection Inspector")
    print("=" * 65)

    if not running:
        print("\nNo running miHoYo game processes detected.")
        print("Discovered games:")
        for g in discovered:
            print(f"  * {g['game_name']} ({g['exe_name']})")
        print("\nLaunch a game and run this command again to inspect live servers.")
        return []

    print("\nRunning Games:")
    for r in running:
        print(f"  * [{r['game_name']}] PID: {r['pid']} ({r['exe_name']})")

    if not connections:
        print("\nNo external remote sockets found yet. (Game might be loading...)")
        return []

    headers = ["Game", "Proto", "Remote Address", "State", "Description"]
    rows = []
    for c in connections:
        r_addr = f"{c['remote_ip']}:{c['remote_port']}"
        desc = "Unknown"
        if c["protocol"] == "UDP" and c["remote_port"] in (22101, 22102):
            desc = "Genshin KCP Game Server"
        elif c["protocol"] == "TCP" and c["remote_port"] in (8999, 443, 80):
            desc = "Dispatch / Gateway Server"
        rows.append([c["game_name"], c["protocol"], r_addr, c["state"], desc])

    print("\nActive Network Connections:")
    print(format_table(headers, rows))
    return connections


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Inspect live miHoYo game connections and optionally add server IPs to monitor."
    )
    parser.add_argument(
        "--watch",
        "-w",
        action="store_true",
        help="Continuously poll and display connections every 3 seconds.",
    )
    parser.add_argument(
        "--add-to-config",
        "-a",
        action="store_true",
        help="Automatically add discovered active game server endpoints to config.json.",
    )
    parser.add_argument(
        "--config",
        "-c",
        default="config.json",
        help="Path to config.json (default: config.json).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format.",
    )
    args = parser.parse_args()

    discovered = discover_installed_games()
    if not discovered:
        launcher_dir = load_launcher_dir(args.config)
        print(f"No games found in '{launcher_dir}'. Check launcher_games_dir in {args.config}.")
        sys.exit(1)

    if args.watch:
        try:
            while True:
                display_status(discovered, args.config)
                time.sleep(3)
        except KeyboardInterrupt:
            print("\nStopped.")
            return

    connections = display_status(discovered, args.config)

    if args.json:
        print(json.dumps(connections, indent=2))
        return

    if args.add_to_config and connections:
        added_count = 0
        for c in connections:
            if c["remote_ip"] not in ("127.0.0.1", "0.0.0.0"):
                name = f"{c['game_name'].split()[0]}-{c['protocol']}-{c['remote_port']}"
                port = c["remote_port"] if c["protocol"] == "TCP" else 443
                if add_endpoint_to_config(name, c["remote_ip"], port, args.config):
                    added_count += 1
        if added_count:
            print(f"\nAdded {added_count} active game endpoint(s) to {args.config}.")


if __name__ == "__main__":
    main()
