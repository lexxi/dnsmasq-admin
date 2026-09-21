import os
import shlex
import shutil
import subprocess

from datetime import datetime
from typing import Dict, Tuple


def run_cmd(
    cmd: str,
    use_sudo: bool = False
) -> Tuple[int, str, str]:
    """
    Führt einen Shell-Befehl ohne shell=True aus.

    Rückgabe:
        returncode, stdout, stderr
    """

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

        return (
            proc.returncode,
            proc.stdout.strip(),
            proc.stderr.strip()
        )

    except Exception as exc:

        return (
            1,
            "",
            str(exc)
        )


def backup_file(
    src: str,
    backup_dir: str
) -> str:
    """
    Erstellt ein zeitgestempeltes Backup.
    """

    if not src:
        raise ValueError(
            "Kein Quellpfad angegeben."
        )

    os.makedirs(
        backup_dir,
        exist_ok=True
    )

    timestamp = datetime.now().strftime(
        "%Y%m%d-%H%M%S"
    )

    filename = os.path.basename(
        src
    )

    dst = os.path.join(
        backup_dir,
        f"{filename}.{timestamp}.bak"
    )

    if os.path.exists(src):

        shutil.copy2(
            src,
            dst
        )

    return dst


def run_hooks(
    cfg: Dict
) -> None:
    """
    Führt nach einer Änderung aus:

      1. convert_hosts.sh
      2. dnsmasq reload

    Bei Fehler wird eine Exception ausgelöst,
    damit die GUI nicht so tut, als wäre alles OK.
    """

    use_sudo = bool(
        cfg.get(
            "allow_sudo",
            False
        )
    )

    generate_script = cfg.get(
        "generate_hosts_script"
    )

    reload_cmd = cfg.get(
        "reload_cmd"
    )

    if generate_script:

        rc, stdout, stderr = run_cmd(
            generate_script,
            use_sudo
        )

        if rc != 0:

            raise RuntimeError(
                "Hosts-Generierung fehlgeschlagen: "
                f"{stderr or stdout or rc}"
            )

    if reload_cmd:

        rc, stdout, stderr = run_cmd(
            reload_cmd,
            use_sudo
        )

        if rc != 0:

            raise RuntimeError(
                "dnsmasq reload fehlgeschlagen: "
                f"{stderr or stdout or rc}"
            )


def remove_lease_by_mac(
    leases_path: str,
    mac: str
) -> Tuple[bool, int, str]:
    """
    Entfernt alle Lease-Einträge für eine MAC.

    WICHTIG:
    Diese Funktion setzt voraus, dass dnsmasq
    bereits gestoppt wurde.

    Rückgabe:
        success
        Anzahl entfernter Zeilen
        Fehlermeldung
    """

    mac = (
        mac
        or ""
    ).strip().lower()

    if not mac:

        return (
            False,
            0,
            "Keine MAC-Adresse angegeben."
        )

    if not os.path.exists(
        leases_path
    ):

        return (
            False,
            0,
            f"Lease-Datei nicht gefunden: "
            f"{leases_path}"
        )

    try:

        with open(
            leases_path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as f:

            lines = f.readlines()

        new_lines = []
        removed = 0

        for line in lines:

            parts = (
                line
                .strip()
                .split()
            )

            # dnsmasq lease format:
            #
            # expiry mac ip hostname clientid
            #
            if (
                len(parts) >= 2
                and parts[1].lower() == mac
            ):

                removed += 1
                continue

            new_lines.append(
                line
            )

        if removed == 0:

            return (
                True,
                0,
                "Keine bestehende Lease gefunden."
            )

        tmp_path = (
            leases_path
            + ".tmp"
        )

        with open(
            tmp_path,
            "w",
            encoding="utf-8"
        ) as f:

            f.writelines(
                new_lines
            )

        # Rechte/Eigentümer vom Original
        # möglichst erhalten.
        stat_info = os.stat(
            leases_path
        )

        os.chmod(
            tmp_path,
            stat_info.st_mode
        )

        try:

            os.chown(
                tmp_path,
                stat_info.st_uid,
                stat_info.st_gid
            )

        except PermissionError:
            pass

        os.replace(
            tmp_path,
            leases_path
        )

        return (
            True,
            removed,
            ""
        )

    except Exception as exc:

        return (
            False,
            0,
            str(exc)
        )


def force_lease_reassign(
    cfg: Dict,
    leases_path: str,
    mac: str
) -> Tuple[bool, str]:
    """
    Erzwingt die Neuvergabe einer DHCP-Adresse:

      1. Lease-Datei sichern
      2. dnsmasq stoppen
      3. Lease der angegebenen MAC löschen
      4. dnsmasq wieder starten

    Das entspricht dem manuellen Ablauf,
    der bisher zuverlässig funktioniert hat.

    Rückgabe:
        success, message
    """

    mac = (
        mac
        or ""
    ).strip().lower()

    if not mac:

        return (
            False,
            "Keine MAC-Adresse angegeben."
        )

    if not leases_path:

        return (
            False,
            "Keine Lease-Datei konfiguriert."
        )

    if not os.path.exists(
        leases_path
    ):

        return (
            False,
            f"Lease-Datei nicht gefunden: "
            f"{leases_path}"
        )

    use_sudo = bool(
        cfg.get(
            "allow_sudo",
            False
        )
    )

    stop_cmd = cfg.get(
        "stop_cmd",
        "systemctl stop dnsmasq"
    )

    start_cmd = cfg.get(
        "start_cmd",
        "systemctl start dnsmasq"
    )

    stopped = False

    #
    # Backup
    #
    try:

        backup_dir = cfg.get(
            "backup_dir",
            "/var/backups/dnsmasq-admin"
        )

        backup_file(
            leases_path,
            backup_dir
        )

    except Exception as exc:

        return (
            False,
            "Backup der Lease-Datei "
            f"fehlgeschlagen: {exc}"
        )

    try:

        #
        # dnsmasq stoppen
        #
        rc, stdout, stderr = run_cmd(
            stop_cmd,
            use_sudo
        )

        if rc != 0:

            return (
                False,
                "dnsmasq konnte nicht "
                "gestoppt werden: "
                f"{stderr or stdout or rc}"
            )

        stopped = True

        #
        # Lease löschen
        #
        success, removed, error = (
            remove_lease_by_mac(
                leases_path,
                mac
            )
        )

        if not success:

            return (
                False,
                "Lease konnte nicht "
                f"gelöscht werden: {error}"
            )

        #
        # dnsmasq starten
        #
        rc, stdout, stderr = run_cmd(
            start_cmd,
            use_sudo
        )

        if rc != 0:

            return (
                False,
                "Lease wurde bearbeitet, "
                "aber dnsmasq konnte nicht "
                "gestartet werden: "
                f"{stderr or stdout or rc}"
            )

        stopped = False

        if removed:

            return (
                True,
                f"{removed} alte Lease(s) "
                f"für {mac} entfernt."
            )

        return (
            True,
            f"Für {mac} war keine alte "
            "Lease vorhanden."
        )

    except Exception as exc:

        return (
            False,
            "Lease-Neuvergabe "
            f"fehlgeschlagen: {exc}"
        )

    finally:

        #
        # Sicherheitsnetz:
        # dnsmasq niemals versehentlich
        # gestoppt zurücklassen.
        #
        if stopped:

            run_cmd(
                start_cmd,
                use_sudo
            )
