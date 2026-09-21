import os
import re
import time
from typing import List, Dict, Tuple, Optional
import ipaddress

DHCP_HOST_PREFIX = "dhcp-host="
MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")
IPV4_RE = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")


class Reservation:
    def __init__(self, mac: str, ip: str, hostname: str = "", raw: str = ""):
        self.mac = mac.lower()
        self.ip = ip
        self.hostname = hostname
        self.raw = raw or self.to_line()

    def to_line(self) -> str:
        parts = [self.mac, self.ip]
        if self.hostname:
            parts.append(self.hostname)
        return f"{DHCP_HOST_PREFIX}{','.join(parts)}"

    def key(self):
        return (self.mac, self.ip)


# ---------- helpers for segments ----------

def _to_ipv4(s):
    try:
        return ipaddress.IPv4Address(s)
    except Exception:
        return None

def ip_in_segment(ip: str, seg: Dict) -> bool:
    if not ip or not isinstance(ip, str):
        return False
    base_ip = _to_ipv4(seg.get("start_ip"))
    ip_obj  = _to_ipv4(ip)
    size    = seg.get("size")
    if base_ip is None or ip_obj is None:
        return False
    try:
        size = int(size)
    except Exception:
        return False
    base = int(base_ip)
    x    = int(ip_obj)
    return base <= x < base + size

def seg_ips(seg: Dict) -> List[str]:
    base_ip = _to_ipv4(seg.get("start_ip"))
    try:
        size = int(seg.get("size"))
    except Exception:
        size = 0
    if base_ip is None or size <= 0:
        return []
    base = int(base_ip)
    return [str(ipaddress.IPv4Address(base + i)) for i in range(size)]

def next_free_ip(seg: Dict, reservations: List[Reservation]) -> Optional[str]:
    if not seg:
        return None
    ips = seg_ips(seg)
    if not ips:
        return None
    used = {r.ip for r in reservations if r.ip in ips}
    for ip in ips:
        if ip not in used:
            return ip
    return None

def collect_segments_usage(reservations: List[Reservation], segments: List[Dict]):
    usage = []
    for seg in segments or []:
        ips = seg_ips(seg)
        used = [r for r in reservations if r.ip in ips]
        usage.append({
            "name": seg["name"],
            "color": seg.get("color", "#e5e7eb"),
            "size": len(ips),
            "used": len(used),
            "free": len(ips) - len(used),
            "ips": ips
        })
    return usage


# ---------- parse/write ----------

def ensure_dir(path: str):
    d = os.path.dirname(path)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)


def parse_dnsmasq_conf(conf_path: str) -> Tuple[List[str], List[Reservation]]:
    lines: List[str] = []
    res: List[Reservation] = []
    if not os.path.exists(conf_path):
        return [], []

    with open(conf_path, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith(DHCP_HOST_PREFIX):
            payload = stripped[len(DHCP_HOST_PREFIX):]
            tokens = [t.strip() for t in payload.split(',') if t.strip()]
            mac = next((t for t in tokens if MAC_RE.match(t)), "")
            ip = next((t for t in tokens if IPV4_RE.match(t)), "")
            hostname = next((t for t in tokens if t not in (mac, ip) and not t.startswith(('tag:', 'set:', 'id:', 'ignore'))), "")
            if mac and ip:
                res.append(Reservation(mac=mac, ip=ip, hostname=hostname, raw=stripped))
    return lines, res


def write_dnsmasq_conf(conf_path: str, all_lines: List[str], new_reservations: List[Reservation]) -> None:
    prefix = DHCP_HOST_PREFIX
    preserved = [ln for ln in all_lines if not ln.strip().startswith(prefix)]

    new_block = [r.to_line() for r in sorted(new_reservations, key=lambda r: (r.hostname or "", r.ip, r.mac))]
    merged = preserved + (["", f"# --- managed by dnsmasq-admin ({len(new_block)} entries) ---"] if new_block else []) + new_block

    ensure_dir(conf_path)
    with open(conf_path, "w", encoding="utf-8") as f:
        f.write("\n".join(merged).rstrip() + "\n")


def upsert_reservation(res: List[Reservation], mac: str, ip: str, hostname: str = "") -> List[Reservation]:
    mac = mac.lower()
    updated: List[Reservation] = []
    found = False
    for r in res:
        if r.mac == mac or r.ip == ip:
            if r.mac == mac:
                r.ip = ip
                if hostname:
                    r.hostname = hostname
                found = True
            elif r.ip == ip:
                r.mac = mac
                if hostname:
                    r.hostname = hostname
                found = True
        updated.append(r)
    if not found:
        updated.append(Reservation(mac=mac, ip=ip, hostname=hostname))
    return updated


def remove_reservation(res: List[Reservation], mac: str = "", ip: str = "", hostname: str = "") -> List[Reservation]:
    mac = mac.lower()
    def match(r: Reservation) -> bool:
        return ((mac and r.mac == mac) or (ip and r.ip == ip) or (hostname and r.hostname == hostname))
    return [r for r in res if not match(r)]

def find_reservation(res: List[Reservation], mac: str = "", ip: str = "") -> Optional[Reservation]:
    mac = (mac or "").lower()
    for r in res:
        if mac and r.mac == mac:
            return r
        if ip and r.ip == ip:
            return r
    return None

def parse_leases(path: str):
    leases = []
    if not os.path.exists(path):
        return leases

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            parts = line.split()
            if len(parts) < 4:
                continue

            expiry = int(parts[0])
            mac = parts[1].lower()
            ip = parts[2]
            hostname = parts[3] if parts[3] != "*" else ""

            now = int(time.time())
            lifetime = expiry - now  # Sekunden

            leases.append({
                "expiry": expiry,
                "lifetime": lifetime,
                "lifetime_min": int(lifetime / 60),
                "lifetime_h": round(lifetime / 3600, 1),
                "mac": mac,
                "ip": ip,
                "hostname": hostname
            })

    return leases

def seg_bounds(seg: Dict):
    """Return (start_int, end_int_inclusive) for a segment, or None if invalid."""
    try:
        start = int(ipaddress.IPv4Address(seg["start_ip"]))
        size = int(seg["size"])
        if size <= 0:
            return None
        return start, start + size - 1
    except Exception:
        return None

def segments_overlap(a: Dict, b: Dict) -> bool:
    ba = seg_bounds(a)
    bb = seg_bounds(b)
    if not ba or not bb:
        return False
    (a0, a1), (b0, b1) = ba, bb
    return not (a1 < b0 or b1 < a0)

def find_overlaps(segments: List[Dict]):
    """Return list of (segA, segB) pairs that overlap."""
    overlaps = []
    for i in range(len(segments)):
        for j in range(i+1, len(segments)):
            if segments_overlap(segments[i], segments[j]):
                overlaps.append((segments[i], segments[j]))
    return overlaps

