import ipaddress

from scapy.all import ARP, DHCP, IP, UDP, Ether, conf

# On a LAN only the router ever sources a packet whose address is public,
# because everything else is behind it. Two is enough to be sure it is not noise,
# and it is reached inside a short capture.
GATEWAY_EXTERNAL_HINT = 2


def _vendor(mac):
    try:
        name = conf.manufdb._get_manuf(mac)
    except Exception:
        return None
    if not name or name.lower() == mac.lower():
        return None
    return name


def _is_randomised(mac):
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def _private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def observe_devices(packets):
    seen = {}

    for packet in packets:
        if Ether not in packet:
            continue
        mac = packet[Ether].src
        if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            continue

        d = seen.get(mac)
        if d is None:
            d = seen[mac] = {
                "mac": mac,
                "local_ips": set(),
                "external_ips": set(),
                "hostnames": set(),
                "packets": 0,
                "bytes": 0,
                "first": None,
                "last": None,
            }

        t = float(packet.time)
        d["packets"] += 1
        d["bytes"] += len(packet)
        d["first"] = t if d["first"] is None else min(d["first"], t)
        d["last"] = t if d["last"] is None else max(d["last"], t)

        if ARP in packet:
            if _private(packet[ARP].psrc):
                d["local_ips"].add(packet[ARP].psrc)
        elif IP in packet:
            src = packet[IP].src
            (d["local_ips"] if _private(src) else d["external_ips"]).add(src)

        if DHCP in packet:
            for opt in packet[DHCP].options:
                if isinstance(opt, tuple) and opt[0] == "hostname":
                    name = opt[1]
                    d["hostnames"].add(name.decode(errors="ignore") if isinstance(name, bytes) else str(name))

    if not seen:
        return []

    origin = min(d["first"] for d in seen.values())

    devices = []
    for d in seen.values():
        external = len(d["external_ips"])
        devices.append({
            "mac": d["mac"],
            "vendor": _vendor(d["mac"]),
            "randomised_mac": _is_randomised(d["mac"]),
            "ips": sorted(d["local_ips"]),
            "hostname": sorted(d["hostnames"])[0] if d["hostnames"] else None,
            "packets": d["packets"],
            "bytes": d["bytes"],
            "first_seen": round(d["first"] - origin, 2),
            "last_seen": round(d["last"] - origin, 2),
            "reaches_internet": external,
            "role": "gateway" if external >= GATEWAY_EXTERNAL_HINT else "device",
        })

    devices.sort(key=lambda x: -x["packets"])
    return devices


def find_new_devices(devices, known_macs):
    known = set(known_macs or ())
    alerts = []
    for d in devices:
        if d["mac"] in known:
            continue
        label = d["hostname"] or d["vendor"] or "an unrecognised device"
        where = d["ips"][0] if d["ips"] else d["mac"]
        alerts.append({
            "kind": "new_device",
            "source": where,
            "target": None,
            "mac": d["mac"],
            "vendor": d["vendor"],
            "count": d["packets"],
            "detail": f"{label} at {where} was not on this network before",
        })
    return alerts
