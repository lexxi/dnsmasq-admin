from flask import Flask, render_template, request, redirect, url_for, flash

import ipaddress
import json
import math
import os

from ipaddress import IPv4Address

from helpers.parser import (
    parse_dnsmasq_conf,
    write_dnsmasq_conf,
    upsert_reservation,
    remove_reservation,
    parse_leases,
    collect_segments_usage,
    next_free_ip,
    ip_in_segment,
    find_reservation,
    find_overlaps,
)

from helpers.system import (
    backup_file,
    run_hooks,
    force_lease_reassign,
)


app = Flask(__name__)
app.secret_key = os.environ.get(
    "DNSMASQ_ADMIN_SECRET",
    "dev-secret"
)


# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CFG_PATH = os.path.join(BASE_DIR, "config.json")

CFG_MTIME = 0.0

CFG = {}
CONF = ""
LEASES = ""
SEGMENTS = []
BACKUP_DIR = "/var/backups/dnsmasq-admin"
CFG_WARNINGS = []


def normalize_cidr(
    val,
    fallback="192.168.1.0/24"
):
    """
    Normalisiert die Netzwerkangabe.

    Unterstützt z.B.:
      192.168.1.0/24
      192.168.1.0
      192.168.1.0 255.255.255.0
    """

    if not val:
        return fallback

    s = str(val).strip()

    # Unsichtbare Zeichen entfernen
    s = (
        s
        .replace("\ufeff", "")
        .replace("\u200b", "")
        .strip()
    )

    # IP + Netmask
    if " " in s:
        try:
            ip_str, mask_str = s.split(None, 1)

            net = ipaddress.IPv4Network(
                (
                    ip_str.strip(),
                    mask_str.strip()
                ),
                strict=False
            )

            return str(net)

        except Exception:
            pass

    # Nur IP angegeben
    if "/" not in s:
        try:
            ipaddress.IPv4Address(s)

            if s.endswith(".0"):
                s = f"{s}/24"
            else:
                s = f"{s}/32"

        except Exception:
            return fallback

    try:
        return str(
            ipaddress.ip_network(
                s,
                strict=False
            )
        )

    except Exception:
        return fallback


def load_config(force=False):
    """
    Lädt config.json bei Änderung neu.
    """

    global CFG
    global CONF
    global LEASES
    global SEGMENTS
    global BACKUP_DIR
    global CFG_MTIME
    global CFG_WARNINGS

    try:
        mtime = os.path.getmtime(CFG_PATH)

    except FileNotFoundError:
        raise RuntimeError(
            f"Config nicht gefunden: {CFG_PATH}"
        )

    if not force and mtime <= CFG_MTIME:
        return

    with open(
        CFG_PATH,
        "r",
        encoding="utf-8"
    ) as f:
        cfg = json.load(f)

    conf = cfg.get(
        "dnsmasq_conf",
        "/etc/dnsmasq.d/dhcp-reservations.conf"
    )

    leases = cfg.get(
        "leases_file",
        "/var/lib/misc/dnsmasq.leases"
    )

    backup_dir = cfg.get(
        "backup_dir",
        "/var/backups/dnsmasq-admin"
    )

    segments = cfg.get(
        "segments",
        []
    ) or []

    valid_segments = []

    for seg in segments:

        if not isinstance(seg, dict):
            continue

        name = str(
            seg.get("name", "")
        ).strip()

        start_ip = str(
            seg.get("start_ip", "")
        ).strip()

        size = seg.get("size")

        if not name or not start_ip:
            continue

        try:
            IPv4Address(start_ip)
            size = int(size)

        except Exception:
            continue

        if size <= 0:
            continue

        seg["name"] = name
        seg["start_ip"] = start_ip
        seg["size"] = size

        valid_segments.append(seg)

    cfg["overview_cidr"] = normalize_cidr(
        cfg.get(
            "overview_cidr",
            "192.168.1.0/24"
        )
    )

    warnings = []

    for a, b in find_overlaps(
        valid_segments
    ):

        warnings.append(
            "Segment-Überlappung: "
            f"'{a.get('name')}' "
            f"({a.get('start_ip')} +{a.get('size')}) "
            "überlappt mit "
            f"'{b.get('name')}' "
            f"({b.get('start_ip')} +{b.get('size')})."
        )

    CFG = cfg
    CONF = conf
    LEASES = leases
    SEGMENTS = valid_segments
    BACKUP_DIR = backup_dir
    CFG_WARNINGS = warnings

    CFG_MTIME = mtime


load_config(force=True)


@app.before_request
def hot_reload_config():

    load_config(force=False)


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------

def segment_for_ip(ip):
    """
    Liefert das Segment für eine IP.
    """

    if not ip:
        return None

    for segment in SEGMENTS:

        if ip_in_segment(
            ip,
            segment
        ):
            return segment

    return None


def get_segment(name):
    """
    Segment anhand des Namens finden.
    """

    return next(
        (
            segment
            for segment in SEGMENTS
            if segment.get("name") == name
        ),
        None
    )


def execute_lease_reassign(
    mac,
    hostname,
    new_ip,
    target
):
    """
    Entfernt optional die bestehende Lease,
    damit der Client nach einem Reboot/Renew
    die neue reservierte Adresse bekommt.
    """

    if not CFG.get(
        "force_lease_reassign_on_move",
        False
    ):

        flash(
            f"{hostname or mac} nach "
            f"{target} verschoben "
            f"(IP {new_ip}).",
            "success"
        )

        return

    success, message = force_lease_reassign(
        CFG,
        LEASES,
        mac
    )

    if success:

        flash(
            f"{hostname or mac} nach "
            f"{target} verschoben "
            f"(IP {new_ip}). "
            f"{message}",
            "success"
        )

    else:

        flash(
            f"{hostname or mac} wurde auf "
            f"{new_ip} verschoben, "
            "aber die alte DHCP-Lease konnte "
            f"nicht entfernt werden: {message}",
            "warning"
        )


# -------------------------------------------------------------------
# Health
# -------------------------------------------------------------------

@app.route("/health")
def health():

    return {
        "status": "ok",
        "config": CFG_PATH,
        "dnsmasq_conf": CONF,
        "leases_file": LEASES,
        "overview_cidr": CFG.get(
            "overview_cidr"
        ),
        "segments": SEGMENTS,
        "warnings": CFG_WARNINGS,
    }, 200


# -------------------------------------------------------------------
# Dashboard
# -------------------------------------------------------------------

@app.route("/")
def index():

    _, reservations = parse_dnsmasq_conf(
        CONF
    )

    leases = parse_leases(
        LEASES
    )

    seg_usage = collect_segments_usage(
        reservations,
        SEGMENTS
    )

    res_by_mac = {}

    for reservation in reservations:

        res_by_mac[
            reservation.mac
        ] = {
            "reservation": reservation,
            "segment": segment_for_ip(
                reservation.ip
            ),
        }

    res_view = []

    for reservation in reservations:

        res_view.append({
            "hostname": reservation.hostname,
            "ip": reservation.ip,
            "mac": reservation.mac,
            "segment": segment_for_ip(
                reservation.ip
            ),
        })

    lease_view = []

    for lease in leases:

        lease_view.append({
            "hostname": lease.get(
                "hostname"
            ),
            "ip": lease.get(
                "ip"
            ),
            "mac": lease.get(
                "mac"
            ),
            "segment": segment_for_ip(
                lease.get("ip")
            ),

            # Falls parse_leases() bereits
            # Lifetime berechnet:
            "expiry": lease.get(
                "expiry"
            ),
            "lifetime": lease.get(
                "lifetime"
            ),
            "lifetime_min": lease.get(
                "lifetime_min"
            ),
            "lifetime_h": lease.get(
                "lifetime_h"
            ),
        })

    return render_template(
        "index.html",
        reservations=res_view,
        leases=lease_view,
        seg_usage=seg_usage,
        segments=SEGMENTS,
        res_by_mac=res_by_mac,
        cfg_warnings=CFG_WARNINGS,
    )


# -------------------------------------------------------------------
# Reservation hinzufügen
# -------------------------------------------------------------------

@app.route(
    "/add",
    methods=["GET", "POST"]
)
def add():

    if request.method == "POST":

        mac = request.form.get(
            "mac",
            ""
        ).strip().lower()

        ip = request.form.get(
            "ip",
            ""
        ).strip()

        hostname = request.form.get(
            "hostname",
            ""
        ).strip()

        segment_name = request.form.get(
            "segment",
            ""
        ).strip()

        if not mac:

            flash(
                "MAC-Adresse fehlt.",
                "warning"
            )

            return redirect(
                url_for("add")
            )

        all_lines, reservations = (
            parse_dnsmasq_conf(CONF)
        )

        if not ip and segment_name:

            segment = get_segment(
                segment_name
            )

            if not segment:

                flash(
                    f"Segment {segment_name} "
                    "nicht gefunden.",
                    "warning"
                )

                return redirect(
                    url_for("add")
                )

            ip = next_free_ip(
                segment,
                reservations
            )

            if not ip:

                flash(
                    f"Segment {segment_name} "
                    "ist voll.",
                    "warning"
                )

                return redirect(
                    url_for("add")
                )

        if not ip:

            flash(
                "IP-Adresse fehlt.",
                "warning"
            )

            return redirect(
                url_for("add")
            )

        new_reservations = upsert_reservation(
            reservations,
            mac=mac,
            ip=ip,
            hostname=hostname
        )

        backup_file(
            CONF,
            BACKUP_DIR
        )

        write_dnsmasq_conf(
            CONF,
            all_lines,
            new_reservations
        )

        run_hooks(CFG)

        flash(
            f"Reservierung für "
            f"{hostname or mac} gespeichert "
            f"(IP {ip}).",
            "success"
        )

        return redirect(
            url_for("index")
        )

    return render_template(
        "form.html",
        segments=SEGMENTS
    )


# -------------------------------------------------------------------
# Reservation löschen
# -------------------------------------------------------------------

@app.route("/delete")
def delete():

    mac = request.args.get(
        "mac",
        ""
    ).strip().lower()

    ip = request.args.get(
        "ip",
        ""
    ).strip()

    hostname = request.args.get(
        "hostname",
        ""
    ).strip()

    all_lines, reservations = (
        parse_dnsmasq_conf(CONF)
    )

    new_reservations = remove_reservation(
        reservations,
        mac=mac,
        ip=ip,
        hostname=hostname
    )

    backup_file(
        CONF,
        BACKUP_DIR
    )

    write_dnsmasq_conf(
        CONF,
        all_lines,
        new_reservations
    )

    run_hooks(CFG)

    flash(
        "Reservierung gelöscht.",
        "info"
    )

    return redirect(
        url_for("index")
    )


# -------------------------------------------------------------------
# Lease fixieren
# -------------------------------------------------------------------

@app.route("/fix")
def fix():

    mac = request.args.get(
        "mac",
        ""
    ).strip().lower()

    ip = request.args.get(
        "ip",
        ""
    ).strip()

    hostname = request.args.get(
        "hostname",
        ""
    ).strip()

    segment_name = request.args.get(
        "segment",
        ""
    ).strip()

    all_lines, reservations = (
        parse_dnsmasq_conf(CONF)
    )

    if segment_name:

        segment = get_segment(
            segment_name
        )

        if not segment:

            flash(
                f"Segment {segment_name} "
                "nicht gefunden.",
                "warning"
            )

            return redirect(
                url_for("index")
            )

        new_ip = next_free_ip(
            segment,
            reservations
        )

        if not new_ip:

            flash(
                f"Segment {segment_name} "
                "ist voll.",
                "warning"
            )

            return redirect(
                url_for("index")
            )

        ip = new_ip

    if not ip:

        flash(
            "Keine IP-Adresse verfügbar.",
            "warning"
        )

        return redirect(
            url_for("index")
        )

    if not hostname:

        hostname = (
            "host-"
            + ip.replace(".", "-")
        )

    new_reservations = upsert_reservation(
        reservations,
        mac=mac,
        ip=ip,
        hostname=hostname
    )

    backup_file(
        CONF,
        BACKUP_DIR
    )

    write_dnsmasq_conf(
        CONF,
        all_lines,
        new_reservations
    )

    run_hooks(CFG)

    flash(
        f"Lease {hostname} "
        f"({mac}) auf {ip} fixiert.",
        "success"
    )

    return redirect(
        url_for("index")
    )


# -------------------------------------------------------------------
# Lease / bestehende Reservation verschieben
# -------------------------------------------------------------------

@app.route("/move")
def move():

    mac = request.args.get(
        "mac",
        ""
    ).strip().lower()

    target = request.args.get(
        "target",
        ""
    ).strip()

    hostname = request.args.get(
        "hostname",
        ""
    ).strip()

    if not mac or not target:

        flash(
            "MAC oder Ziel-Segment fehlt.",
            "warning"
        )

        return redirect(
            url_for("index")
        )

    all_lines, reservations = (
        parse_dnsmasq_conf(CONF)
    )

    reservation = find_reservation(
        reservations,
        mac=mac
    )

    if not reservation:

        flash(
            "Keine bestehende Reservierung "
            "für diese MAC gefunden.",
            "warning"
        )

        return redirect(
            url_for("index")
        )

    segment = get_segment(
        target
    )

    if not segment:

        flash(
            f"Ziel-Segment {target} "
            "nicht gefunden.",
            "warning"
        )

        return redirect(
            url_for("index")
        )

    new_ip = next_free_ip(
        segment,
        reservations
    )

    if not new_ip:

        flash(
            f"Segment {target} ist voll.",
            "warning"
        )

        return redirect(
            url_for("index")
        )

    old_ip = reservation.ip

    if hostname:
        reservation.hostname = hostname

    reservation.ip = new_ip

    backup_file(
        CONF,
        BACKUP_DIR
    )

    write_dnsmasq_conf(
        CONF,
        all_lines,
        reservations
    )

    # /etc/hosts erzeugen +
    # dnsmasq reload
    run_hooks(CFG)

    execute_lease_reassign(
        mac=mac,
        hostname=reservation.hostname,
        new_ip=new_ip,
        target=target
    )

    return redirect(
        url_for("index")
    )


@app.route("/move_existing")
def move_existing():

    mac = request.args.get(
        "mac",
        ""
    ).strip().lower()

    target = request.args.get(
        "target",
        ""
    ).strip()

    if not mac or not target:

        flash(
            "MAC oder Ziel-Segment fehlt.",
            "warning"
        )

        return redirect(
            url_for("index")
        )

    all_lines, reservations = (
        parse_dnsmasq_conf(CONF)
    )

    reservation = find_reservation(
        reservations,
        mac=mac
    )

    if not reservation:

        flash(
            "Keine bestehende Reservierung "
            "gefunden.",
            "warning"
        )

        return redirect(
            url_for("index")
        )

    segment = get_segment(
        target
    )

    if not segment:

        flash(
            f"Ziel-Segment {target} "
            "nicht gefunden.",
            "warning"
        )

        return redirect(
            url_for("index")
        )

    current_segment = segment_for_ip(
        reservation.ip
    )

    if (
        current_segment
        and current_segment.get("name") == target
    ):

        flash(
            f"{reservation.hostname or mac} "
            f"ist bereits im Segment {target}.",
            "info"
        )

        return redirect(
            url_for("index")
        )

    new_ip = next_free_ip(
        segment,
        reservations
    )

    if not new_ip:

        flash(
            f"Segment {target} ist voll.",
            "warning"
        )

        return redirect(
            url_for("index")
        )

    old_ip = reservation.ip
    reservation.ip = new_ip

    backup_file(
        CONF,
        BACKUP_DIR
    )

    write_dnsmasq_conf(
        CONF,
        all_lines,
        reservations
    )

    run_hooks(CFG)

    execute_lease_reassign(
        mac=mac,
        hostname=reservation.hostname,
        new_ip=new_ip,
        target=target
    )

    return redirect(
        url_for("index")
    )


# -------------------------------------------------------------------
# Segment-Konfiguration
# -------------------------------------------------------------------

@app.route(
    "/config",
    methods=["GET", "POST"]
)
def config_editor():

    if request.method == "POST":

        try:

            names = request.form.getlist(
                "name"
            )

            colors = request.form.getlist(
                "color"
            )

            start_ips = request.form.getlist(
                "start_ip"
            )

            sizes = request.form.getlist(
                "size"
            )

            prefixes = request.form.getlist(
                "hostname_prefix"
            )

            new_segments = []
            names_seen = set()

            for i in range(
                len(names)
            ):

                name = names[i].strip()

                color = (
                    colors[i].strip()
                    if i < len(colors)
                    else "#ffffff"
                )

                start_ip = (
                    start_ips[i].strip()
                    if i < len(start_ips)
                    else ""
                )

                size_raw = (
                    sizes[i].strip()
                    if i < len(sizes)
                    else ""
                )

                prefix = (
                    prefixes[i].strip()
                    if i < len(prefixes)
                    else ""
                )

                # Leere Zusatzzeile
                if (
                    not name
                    and not start_ip
                    and not size_raw
                ):
                    continue

                if (
                    not name
                    or not start_ip
                    or not size_raw
                ):

                    flash(
                        "Unvollständiges Segment "
                        "übersprungen.",
                        "warning"
                    )

                    continue

                if name in names_seen:

                    flash(
                        f"Doppelter Segmentname: "
                        f"{name}",
                        "warning"
                    )

                    continue

                try:

                    IPv4Address(start_ip)
                    size = int(size_raw)

                    if size <= 0:
                        raise ValueError(
                            "size <= 0"
                        )

                except Exception:

                    flash(
                        f"Ungültiges Segment: "
                        f"{name}",
                        "warning"
                    )

                    continue

                names_seen.add(name)

                new_segments.append({
                    "name": name,
                    "color": color or "#ffffff",
                    "start_ip": start_ip,
                    "size": size,
                    "hostname_prefix": prefix,
                })

            overlaps = find_overlaps(
                new_segments
            )

            if overlaps:

                for a, b in overlaps:

                    flash(
                        "Überschneidung: "
                        f"{a.get('name')} und "
                        f"{b.get('name')}.",
                        "warning"
                    )

                return render_template(
                    "config.html",
                    segments=new_segments
                )

            CFG["segments"] = new_segments

            with open(
                CFG_PATH,
                "w",
                encoding="utf-8"
            ) as f:

                json.dump(
                    CFG,
                    f,
                    indent=2,
                    ensure_ascii=False
                )

                f.write("\n")

            load_config(
                force=True
            )

            flash(
                "Konfiguration gespeichert.",
                "success"
            )

            return redirect(
                url_for("config_editor")
            )

        except Exception as exc:

            flash(
                f"Fehler beim Speichern: {exc}",
                "danger"
            )

    return render_template(
        "config.html",
        segments=SEGMENTS
    )


@app.route(
    "/reload",
    methods=["POST"]
)
def manual_reload():

    load_config(
        force=True
    )

    flash(
        "Konfiguration neu geladen.",
        "success"
    )

    return redirect(
        url_for("index")
    )


# -------------------------------------------------------------------
# Netzwerk-Übersicht
# -------------------------------------------------------------------

@app.route("/overview")
def overview():

    _, reservations = parse_dnsmasq_conf(
        CONF
    )

    leases = parse_leases(
        LEASES
    )

    cidr = CFG.get(
        "overview_cidr",
        "192.168.1.0/24"
    )

    try:

        net = ipaddress.ip_network(
            cidr,
            strict=False
        )

    except Exception:

        flash(
            f"Ungültiges overview_cidr: "
            f"{repr(cidr)}",
            "warning"
        )

        return redirect(
            url_for("index")
        )

    if net.version != 4:

        flash(
            "Die Übersicht unterstützt "
            "derzeit nur IPv4.",
            "warning"
        )

        return redirect(
            url_for("index")
        )

    show_leases = bool(
        CFG.get(
            "show_leases_in_overview",
            True
        )
    )

    reservation_ips = {
        reservation.ip: reservation
        for reservation in reservations
    }

    lease_ips = {
        lease.get("ip"): lease
        for lease in leases
        if lease.get("ip")
    }

    addresses = [
        str(ip)
        for ip in net.hosts()
    ]

    if len(addresses) > 4096:

        flash(
            "Netz zu groß für Übersicht "
            "(mehr als 4096 Hosts).",
            "warning"
        )

        return redirect(
            url_for("index")
        )

    cells = []

    for ip in addresses:

        segment = segment_for_ip(
            ip
        )

        kind = "free"
        mark = ""

        reservation = (
            reservation_ips.get(ip)
        )

        lease = (
            lease_ips.get(ip)
        )

        if reservation:

            kind = "reservation"
            mark = "×"

        elif show_leases and lease:

            kind = "lease"
            mark = "•"

        cells.append({
            "ip": ip,
            "segment": (
                segment.get("name")
                if segment
                else ""
            ),
            "color": (
                segment.get(
                    "color",
                    "#ffffff"
                )
                if segment
                else "#ffffff"
            ),
            "kind": kind,
            "mark": mark,
            "hostname": (
                reservation.hostname
                if reservation
                else (
                    lease.get("hostname")
                    if lease
                    else ""
                )
            ),
        })

    cols = 16

    if cells:

        cols = max(
            8,
            min(
                32,
                int(
                    math.sqrt(
                        len(cells)
                    )
                )
            )
        )

    return render_template(
        "overview.html",
        cells=cells,
        cols=cols,
        cidr=str(net),
        cfg_warnings=CFG_WARNINGS,
    )


# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------

if __name__ == "__main__":

    host = os.environ.get(
        "DNSMASQ_ADMIN_HOST",
        "0.0.0.0"
    )

    port = int(
        os.environ.get(
            "DNSMASQ_ADMIN_PORT",
            "8088"
        )
    )

    debug = (
        os.environ.get(
            "DNSMASQ_ADMIN_DEBUG",
            "0"
        )
        == "1"
    )

    app.run(
        host=host,
        port=port,
        debug=debug,
        threaded=True
    )
