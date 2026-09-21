import os
import shlex
import shutil
import subprocess

from datetime import datetime
from typing import Dict, Tuple


def run_cmd(cmd: str, use_sudo: bool = False) -> Tuple[int, str, str]:
    if not cmd:
        return 0, "", ""

    args = shlex.split(cmd)
    if use_sudo:
        args = ["sudo"] + args

    try:
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except Exception as exc:
        return 1, "", str(exc)


def backup_file(src: str, backup_dir: str) -> str:
    if not src:
        raise ValueError("No source path supplied.")

    os.makedirs(backup_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = os.path.basename(src)
    dst = os.path.join(backup_dir, f"{filename}.{timestamp}.bak")

    if os.path.exists(src):
        shutil.copy2(src, dst)

    return dst


def run_hooks(cfg: Dict) -> None:
    use_sudo = bool(cfg.get("allow_sudo", False))
    generate_script = cfg.get("generate_hosts_script")
    reload_cmd = cfg.get("reload_cmd")

    if generate_script:
        rc, stdout, stderr = run_cmd(generate_script, use_sudo)
        if rc != 0:
            raise RuntimeError(
                "Host generation failed: "
                f"{stderr or stdout or rc}"
            )

    if reload_cmd:
        rc, stdout, stderr = run_cmd(reload_cmd, use_sudo)
        if rc != 0:
            raise RuntimeError(
                "dnsmasq reload failed: "
                f"{stderr or stdout or rc}"
            )


def remove_lease_by_mac(leases_path: str, mac: str) -> Tuple[bool, int, str]:
    mac = (mac or "").strip().lower()

    if not mac:
        return False, 0, "No MAC address supplied."

    if not os.path.exists(leases_path):
        return False, 0, f"Lease file not found: {leases_path}"

    try:
        with open(leases_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        new_lines = []
        removed = 0

        for line in lines:
            parts = line.strip().split()
            if len(parts) >= 2 and parts[1].lower() == mac:
                removed += 1
                continue
            new_lines.append(line)

        if removed == 0:
            return True, 0, "No existing lease found."

        tmp_path = leases_path + ".tmp"

        with open(tmp_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

        stat_info = os.stat(leases_path)
        os.chmod(tmp_path, stat_info.st_mode)

        try:
            os.chown(tmp_path, stat_info.st_uid, stat_info.st_gid)
        except PermissionError:
            pass

        os.replace(tmp_path, leases_path)
        return True, removed, ""

    except Exception as exc:
        return False, 0, str(exc)


def force_lease_reassign(cfg: Dict, leases_path: str, mac: str) -> Tuple[bool, str]:
    mac = (mac or "").strip().lower()

    if not mac:
        return False, "No MAC address supplied."

    if not leases_path:
        return False, "No lease file configured."

    if not os.path.exists(leases_path):
        return False, f"Lease file not found: {leases_path}"

    use_sudo = bool(cfg.get("allow_sudo", False))
    stop_cmd = cfg.get("stop_cmd", "systemctl stop dnsmasq")
    start_cmd = cfg.get("start_cmd", "systemctl start dnsmasq")
    stopped = False

    try:
        backup_dir = cfg.get("backup_dir", "/var/backups/dnsmasq-admin")
        backup_file(leases_path, backup_dir)
    except Exception as exc:
        return False, f"Lease backup failed: {exc}"

    try:
        rc, stdout, stderr = run_cmd(stop_cmd, use_sudo)
        if rc != 0:
            return False, f"dnsmasq could not be stopped: {stderr or stdout or rc}"

        stopped = True

        success, removed, error = remove_lease_by_mac(leases_path, mac)
        if not success:
            return False, f"Lease could not be removed: {error}"

        rc, stdout, stderr = run_cmd(start_cmd, use_sudo)
        if rc != 0:
            return False, (
                "Lease was modified, but dnsmasq could not be started: "
                f"{stderr or stdout or rc}"
            )

        stopped = False

        if removed:
            return True, f"Removed {removed} old lease(s) for {mac}."

        return True, f"No old lease existed for {mac}."

    except Exception as exc:
        return False, f"Lease reassignment failed: {exc}"

    finally:
        if stopped:
            run_cmd(start_cmd, use_sudo)
