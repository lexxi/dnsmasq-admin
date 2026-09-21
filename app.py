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
from helpers.system import backup_file, run_hooks, force_lease_reassign


app = Flask(__name__)
app.secret_key = os.environ.get("DNSMASQ_ADMIN_SECRET", "dev-secret")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CFG_PATH = os.path.join(BASE_DIR, "config.json")
CFG_MTIME = 0.0
CFG = {}
CONF = ""
LEASES = ""
SEGMENTS = []
BACKUP_DIR = "/var/backups/dnsmasq-admin"
CFG_WARNINGS = []


def normalize_cidr(val, fallback="192.168.1.0/24"):
    if not val:
        return fallback

    s = str(val).replace("\ufeff", "").replace("\u200b", "").strip()

    if " " in s:
        try:
            ip_str, mask_str = s.split(None, 1)
            return str(ipaddress.IPv4Network((ip_str.strip(), mask_str.strip()), strict=False))
        except Exception:
            pass

    if "/" not in s:
        try:
            ipaddress.IPv4Address(s)
            s = f"{s}/24" if s.endswith(".0") else f"{s}/32"
        except Exception:
            return fallback

    try:
        return str(ipaddress.ip_network(s, strict=False))
    except Exception:
        return fallback


def load_config(force=False):
    global CFG, CONF, LEASES, SEGMENTS, BACKUP_DIR, CFG_MTIME, CFG_WARNINGS

    try:
        mtime = os.path.getmtime(CFG_PATH)
    except FileNotFoundError:
        raise RuntimeError(
            f"Config not found: {CFG_PATH}. Copy config.example.json to config.json first."
        )

    if not force and mtime <= CFG_MTIME:
        return

    with open(CFG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    conf = cfg.get("dnsmasq_conf", "/etc/dnsmasq.d/dhcp-reservations.conf")
    leases = cfg.get("leases_file", "/var/lib/misc/dnsmasq.leases")
    backup_dir = cfg.get("backup_dir", "/var/backups/dnsmasq-admin")
    segments = cfg.get("segments", []) or []

    valid_segments = []
    for seg in segments:
        if not isinstance(seg, dict):
            continue

        name = str(seg.get("name", "")).strip()
        start_ip = str(seg.get("start_ip", "")).strip()
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

        clean = dict(seg)
        clean["name"] = name
        clean["start_ip"] = start_ip
        clean["size"] = size
        valid_segments.append(clean)

    cfg["overview_cidr"] = normalize_cidr(cfg.get("overview_cidr", "192.168.1.0/24"))

    warnings = []
    for a, b in find_overlaps(valid_segments):
        warnings.append(
            f"Segment-Überlappung: '{a.get('name')}' "
            f"({a.get('start_ip')} +{a.get('size')}) überlappt mit "
            f"'{b.get('name')}' ({b.get('start_ip')} +{b.get('size')})."
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


def segment_for_ip(ip):
    if not ip:
        return None
    for segment in SEGMENTS:
        if ip_in_segment(ip, segment):
            return segment
    return None


def get_segment(name):
    return next((segment for segment in SEGMENTS if segment.get("name") == name), None)


def save_reservations(all_lines, reservations):
    backup_file(CONF, BACKUP_DIR)
    write_dnsmasq_conf(CONF, all_lines, reservations)
    run_hooks(CFG)


def reassign_lease_if_enabled(mac):
    if not CFG.get("force_lease_reassign_on_move", False):
        return True, ""
    return force_lease_reassign(CFG, LEASES, mac)


@app.route("/health")
def health():
    return {
        "status": "ok",
        "config": CFG_PATH,
        "dnsmasq_conf": CONF,
        "leases_file": LEASES,
        "overview_cidr": CFG.get("overview_cidr"),
        "segments": SEGMENTS,
        "warnings": CFG_WARNINGS,
    }, 200


@app.route("/")
def index():
    _, reservations = parse_dnsmasq_conf(CONF)
    leases = parse_leases(LEASES)
    seg_usage = collect_segments_usage(reservations, SEGMENTS)

    res_by_mac = {
        r.mac: {"reservation": r, "segment": segment_for_ip(r.ip)}
        for r in reservations
    }

    res_view = [
        {
            "hostname": r.hostname,
            "ip": r.ip,
            "mac": r.mac,
            "segment": segment_for_ip(r.ip),
        }
        for r in reservations
    ]

    lease_view = [
        {
            "hostname": l.get("hostname"),
            "ip": l.get("ip"),
            "mac": l.get("mac"),
            "segment": segment_for_ip(l.get("ip")),
            "expiry": l.get("expiry"),
            "lifetime": l.get("lifetime"),
            "lifetime_min": l.get("lifetime_min"),
            "lifetime_h": l.get("lifetime_h"),
        }
        for l in leases
    ]

    return render_template(
        "index.html",
        reservations=res_view,
        leases=lease_view,
        seg_usage=seg_usage,
        segments=SEGMENTS,
        res_by_mac=res_by_mac,
        cfg_warnings=CFG_WARNINGS,
    )


@app.route("/add", methods=["GET", "POST"])
def add():
    if request.method == "POST":
        mac = request.form.get("mac", "").strip().lower()
        ip = request.form.get("ip", "").strip()
        hostname = request.form.get("hostname", "").strip()
        segment_name = request.form.get("segment", "").strip()

        if not mac:
            flash("MAC-Adresse fehlt.", "warning")
            return redirect(url_for("add"))

        all_lines, reservations = parse_dnsmasq_conf(CONF)

        if not ip and segment_name:
            segment = get_segment(segment_name)
            if not segment:
                flash(f"Segment {segment_name} nicht gefunden.", "warning")
                return redirect(url_for("add"))

            ip = next_free_ip(segment, reservations)
            if not ip:
                flash(f"Segment {segment_name} ist voll.", "warning")
                return redirect(url_for("add"))

        if not ip:
            flash("IP-Adresse fehlt.", "warning")
            return redirect(url_for("add"))

        reservations = upsert_reservation(reservations, mac=mac, ip=ip, hostname=hostname)
        save_reservations(all_lines, reservations)

        flash(f"Reservierung für {hostname or mac} gespeichert (IP {ip}).", "success")
        return redirect(url_for("index"))

    return render_template("form.html", segments=SEGMENTS, cfg_warnings=CFG_WARNINGS)


@app.route("/delete")
def delete():
    mac = request.args.get("mac", "").strip().lower()
    ip = request.args.get("ip", "").strip()
    hostname = request.args.get("hostname", "").strip()

    all_lines, reservations = parse_dnsmasq_conf(CONF)
    reservations = remove_reservation(reservations, mac=mac, ip=ip, hostname=hostname)
    save_reservations(all_lines, reservations)

    flash("Reservierung gelöscht.", "info")
    return redirect(url_for("index"))


@app.route("/fix")
def fix():
    mac = request.args.get("mac", "").strip().lower()
    ip = request.args.get("ip", "").strip()
    hostname = request.args.get("hostname", "").strip()
    segment_name = request.args.get("segment", "").strip()

    if not mac:
        flash("MAC-Adresse fehlt.", "warning")
        return redirect(url_for("index"))

    all_lines, reservations = parse_dnsmasq_conf(CONF)

    if segment_name:
        segment = get_segment(segment_name)
        if not segment:
            flash(f"Segment {segment_name} nicht gefunden.", "warning")
            return redirect(url_for("index"))

        new_ip = next_free_ip(segment, reservations)
        if not new_ip:
            flash(f"Segment {segment_name} ist voll.", "warning")
            return redirect(url_for("index"))
        ip = new_ip

    if not ip:
        flash("Keine IP-Adresse verfügbar.", "warning")
        return redirect(url_for("index"))

    if not hostname:
        hostname = "host-" + ip.replace(".", "-")

    reservations = upsert_reservation(reservations, mac=mac, ip=ip, hostname=hostname)
    save_reservations(all_lines, reservations)

    success, message = reassign_lease_if_enabled(mac)
    if success:
        flash(f"Lease {hostname} ({mac}) auf {ip} fixiert. {message}", "success")
    else:
        flash(
            f"Reservierung wurde auf {ip} gesetzt, aber die alte Lease konnte "
            f"nicht entfernt werden: {message}",
            "warning",
        )

    return redirect(url_for("index"))


@app.route("/move")
def move():
    mac = request.args.get("mac", "").strip().lower()
    target = request.args.get("target", "").strip()
    hostname = request.args.get("hostname", "").strip()

    if not mac or not target:
        flash("MAC oder Ziel-Segment fehlt.", "warning")
        return redirect(url_for("index"))

    all_lines, reservations = parse_dnsmasq_conf(CONF)
    reservation = find_reservation(reservations, mac=mac)

    if not reservation:
        flash("Keine bestehende Reservierung für diese MAC gefunden.", "warning")
        return redirect(url_for("index"))

    segment = get_segment(target)
    if not segment:
        flash(f"Ziel-Segment {target} nicht gefunden.", "warning")
        return redirect(url_for("index"))

    new_ip = next_free_ip(segment, reservations)
    if not new_ip:
        flash(f"Segment {target} ist voll.", "warning")
        return redirect(url_for("index"))

    if hostname:
        reservation.hostname = hostname
    reservation.ip = new_ip

    save_reservations(all_lines, reservations)
    success, message = reassign_lease_if_enabled(mac)

    if success:
        flash(
            f"{reservation.hostname or mac} nach Segment {target} verschoben "
            f"(IP {new_ip}). {message}",
            "success",
        )
    else:
        flash(
            f"{reservation.hostname or mac} wurde auf {new_ip} verschoben, "
            f"aber die alte DHCP-Lease konnte nicht entfernt werden: {message}",
            "warning",
        )

    return redirect(url_for("index"))


@app.route("/move_existing")
def move_existing():
    mac = request.args.get("mac", "").strip().lower()
    target = request.args.get("target", "").strip()

    if not mac or not target:
        flash("MAC oder Ziel-Segment fehlt.", "warning")
        return redirect(url_for("index"))

    all_lines, reservations = parse_dnsmasq_conf(CONF)
    reservation = find_reservation(reservations, mac=mac)

    if not reservation:
        flash("Keine bestehende Reservierung gefunden.", "warning")
        return redirect(url_for("index"))

    segment = get_segment(target)
    if not segment:
        flash(f"Ziel-Segment {target} nicht gefunden.", "warning")
        return redirect(url_for("index"))

    current_segment = segment_for_ip(reservation.ip)
    if current_segment and current_segment.get("name") == target:
        flash(f"{reservation.hostname or mac} ist bereits im Segment {target}.", "info")
        return redirect(url_for("index"))

    new_ip = next_free_ip(segment, reservations)
    if not new_ip:
        flash(f"Segment {target} ist voll.", "warning")
        return redirect(url_for("index"))

    reservation.ip = new_ip
    save_reservations(all_lines, reservations)
    success, message = reassign_lease_if_enabled(mac)

    if success:
        flash(
            f"{reservation.hostname or mac} nach Segment {target} verschoben "
            f"(IP {new_ip}). {message}",
            "success",
        )
    else:
        flash(
            f"{reservation.hostname or mac} wurde auf {new_ip} verschoben, "
            f"aber die alte DHCP-Lease konnte nicht entfernt werden: {message}",
            "warning",
        )

    return redirect(url_for("index"))


@app.route("/config", methods=["GET", "POST"])
def config_editor():
    if request.method == "POST":
        try:
            names = request.form.getlist("name")
            colors = request.form.getlist("color")
            start_ips = request.form.getlist("start_ip")
            sizes = request.form.getlist("size")
            prefixes = request.form.getlist("hostname_prefix")

            new_segments = []
            names_seen = set()

            for i in range(len(names)):
                name = names[i].strip()
                color = colors[i].strip() if i < len(colors) else "#ffffff"
                start_ip = start_ips[i].strip() if i < len(start_ips) else ""
                size_raw = sizes[i].strip() if i < len(sizes) else ""
                prefix = prefixes[i].strip() if i < len(prefixes) else ""

                if not name and not start_ip and not size_raw:
                    continue

                if not name or not start_ip or not size_raw:
                    flash("Unvollständiges Segment übersprungen.", "warning")
                    continue

                if name in names_seen:
                    flash(f"Doppelter Segmentname: {name}", "warning")
                    continue

                try:
                    IPv4Address(start_ip)
                    size = int(size_raw)
                    if size <= 0:
                        raise ValueError("size <= 0")
                except Exception:
                    flash(f"Ungültiges Segment: {name}", "warning")
                    continue

                names_seen.add(name)
                new_segments.append({
                    "name": name,
                    "color": color or "#ffffff",
                    "start_ip": start_ip,
                    "size": size,
                    "hostname_prefix": prefix,
                })

            overlaps = find_overlaps(new_segments)
            if overlaps:
                for a, b in overlaps:
                    flash(
                        f"Überschneidung: {a.get('name')} und {b.get('name')}.",
                        "warning",
                    )
                return render_template(
                    "config.html",
                    segments=new_segments,
                    cfg_warnings=CFG_WARNINGS,
                )

            CFG["segments"] = new_segments

            with open(CFG_PATH, "w", encoding="utf-8") as f:
                json.dump(CFG, f, indent=2, ensure_ascii=False)
                f.write("\n")

            load_config(force=True)
            flash("Konfiguration gespeichert.", "success")
            return redirect(url_for("config_editor"))

        except Exception as exc:
            flash(f"Fehler beim Speichern: {exc}", "danger")

    return render_template(
        "config.html",
        segments=SEGMENTS,
        cfg_warnings=CFG_WARNINGS,
    )


@app.route("/reload", methods=["POST"])
def manual_reload():
    load_config(force=True)
    flash("Konfiguration neu geladen.", "success")
    return redirect(url_for("index"))


@app.route("/overview")
def overview():
    _, reservations = parse_dnsmasq_conf(CONF)
    leases = parse_leases(LEASES)
    cidr = CFG.get("overview_cidr", "192.168.1.0/24")

    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except Exception:
        flash(f"Ungültiges overview_cidr: {repr(cidr)}", "warning")
        return redirect(url_for("index"))

    if net.version != 4:
        flash("Die Übersicht unterstützt derzeit nur IPv4.", "warning")
        return redirect(url_for("index"))

    show_leases = bool(CFG.get("show_leases_in_overview", True))
    reservation_ips = {r.ip: r for r in reservations}
    lease_ips = {l.get("ip"): l for l in leases if l.get("ip")}
    addresses = [str(ip) for ip in net.hosts()]

    if len(addresses) > 4096:
        flash("Netz zu groß für Übersicht (mehr als 4096 Hosts).", "warning")
        return redirect(url_for("index"))

    cells = []
    for ip in addresses:
        segment = segment_for_ip(ip)
        reservation = reservation_ips.get(ip)
        lease = lease_ips.get(ip)

        kind = "free"
        mark = ""
        if reservation:
            kind = "reservation"
            mark = "×"
        elif show_leases and lease:
            kind = "lease"
            mark = "•"

        cells.append({
            "ip": ip,
            "segment": segment.get("name") if segment else "",
            "color": segment.get("color", "#ffffff") if segment else "#ffffff",
            "kind": kind,
            "mark": mark,
            "hostname": (
                reservation.hostname
                if reservation
                else (lease.get("hostname") if lease else "")
            ),
        })

    cols = 16
    if cells:
        cols = max(8, min(32, int(math.sqrt(len(cells)))))

    return render_template(
        "overview.html",
        cells=cells,
        cols=cols,
        cidr=str(net),
        cfg_warnings=CFG_WARNINGS,
    )


if __name__ == "__main__":
    host = os.environ.get("DNSMASQ_ADMIN_HOST", "0.0.0.0")
    port = int(os.environ.get("DNSMASQ_ADMIN_PORT", "8088"))
    debug = os.environ.get("DNSMASQ_ADMIN_DEBUG", "0") == "1"
    app.run(host=host, port=port, debug=debug, threaded=True)
