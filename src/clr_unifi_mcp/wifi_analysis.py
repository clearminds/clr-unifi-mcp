"""Per-client Wi-Fi experience analysis over UniFi system-log events.

Pure functions: no controller access, so they are unit-testable with synthetic
events. ``server.wifi_experience_report`` feeds them rows from
``list_events(raw=True)`` plus an identity map.

Everything reported is a *symptom* derived from controller events (drops,
roaming, signal) -- not a throughput measurement.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

# Heuristic weights: higher score = worse experience. Exposed in the report so
# the numbers can be audited; compare clients within one report, not across them.
WEIGHTS = {
    "auth_failures": 3.0,
    "ping_pong": 2.0,
    "flaps": 1.5,
    "drops": 1.0,
    "short_sessions": 1.0,
    "weak_events": 0.5,
    "roams": 0.25,
}
IOT_HOSTNAMES = r"tasmota|relay|esp[-_0-9a-f]|shelly"
_FAIL_KEY = re.compile(r"AUTH|FAIL|DENIED|REJECT|RADIUS|TIMEOUT")


def _name(params: dict[str, Any], key: str) -> str | None:
    """``params[key]`` as text: entities are {"name": ...}, some are plain strings."""
    val = params.get(key)
    if isinstance(val, dict):
        val = val.get("name")
    return str(val) if val not in (None, "") else None


def _int(val: Any) -> int | None:
    try:
        return int(float(val))
    except (TypeError, ValueError):
        return None


def classify(key: str) -> str:
    k = (key or "").upper()
    if _FAIL_KEY.search(k):
        return "fail"
    if "ROAM" in k:
        return "roam"
    if "DISCONNECT" in k:
        return "disconnect"
    if "CONNECT" in k:
        return "connect"
    return "other"


def parse_events(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalise ``list_events(raw=True)`` rows. Rows without a client MAC,
    a timestamp, or a connect/disconnect/roam/fail kind are dropped."""
    out = []
    for r in rows:
        kind = classify(r.get("key", ""))
        mac = (r.get("mac") or "").lower()
        ts = r.get("timestamp")
        if kind == "other" or not mac or ts is None:
            continue
        p = r.get("params") if isinstance(r.get("params"), dict) else {}
        client = p.get("CLIENT") if isinstance(p.get("CLIENT"), dict) else {}
        ap = r.get("device") or ""
        ap_from = None
        if kind == "roam":
            ap_from = _name(p, "DEVICE_FROM")
            ap = _name(p, "DEVICE_TO") or ap
        out.append(
            {
                "ts": int(ts),
                "kind": kind,
                "mac": mac,
                "ap": ap,
                "ap_from": ap_from,
                "ssid": r.get("ssid") or _name(p, "WLAN"),
                "ip": client.get("ip") or _name(p, "IP"),
                "hostname": client.get("hostname") or client.get("name") or "",
                "signal": _int(_name(p, "SIGNAL_STRENGTH")),
                "prev_signal": _int(_name(p, "PREVIOUS_SIGNAL_STRENGTH")),
                "band": _name(p, "RADIO_BAND"),
                "prev_band": _name(p, "PREVIOUS_RADIO_BAND"),
                "channel": _name(p, "CHANNEL"),
                "utilization": _int(_name(p, "AVG_UTILIZATION")),
                "interference": _int(_name(p, "AVG_INTERFERENCE")),
                # Disconnect events report the session length; DURATION.id is seconds.
                "duration_s": _int((p.get("DURATION") or {}).get("id"))
                if isinstance(p.get("DURATION"), dict)
                else None,
            }
        )
    out.sort(key=lambda e: e["ts"])
    return out


def _iso(ts: int | None) -> str | None:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() if ts else None


def _band_flip(e: dict[str, Any]) -> bool:
    return bool(e["prev_band"] and e["band"] and e["prev_band"] != e["band"])


def _to_weaker(e: dict[str, Any]) -> bool:
    return (
        e["signal"] is not None
        and e["prev_signal"] is not None
        and e["signal"] < e["prev_signal"] - 3
    )


def _client_metrics(
    ev: list[dict[str, Any]],
    *,
    flap_s: int,
    pingpong_s: int,
    short_s: int,
    weak_dbm: int,
) -> dict[str, Any]:
    connects = [e for e in ev if e["kind"] == "connect"]
    disconnects = [e for e in ev if e["kind"] == "disconnect"]
    roams = [e for e in ev if e["kind"] == "roam"]

    # flap: disconnect followed by a reconnect to the same AP within flap_s
    flaps = 0
    for d in disconnects:
        nxt = next((c for c in connects if c["ts"] >= d["ts"]), None)
        if nxt and nxt["ap"] == d["ap"] and nxt["ts"] - d["ts"] <= flap_s:
            flaps += 1

    # ping-pong: A->B then B->A within pingpong_s. Roams carry both APs; if the
    # dump had none (older controller payloads) fall back to connect-AP order.
    ping_pong = 0
    moves = [
        (r["ap_from"], r["ap"], r["ts"]) for r in roams if r["ap_from"] and r["ap"]
    ]
    if moves:
        for (a0, b0, t0), (a1, b1, t1) in zip(moves, moves[1:]):
            if a1 == b0 and b1 == a0 and t1 - t0 <= pingpong_s:
                ping_pong += 1
    else:
        seq = [(c["ap"], c["ts"]) for c in connects]
        for i in range(2, len(seq)):
            if (
                seq[i][0] == seq[i - 2][0] != seq[i - 1][0]
                and seq[i][1] - seq[i - 2][1] <= pingpong_s
            ):
                ping_pong += 1

    # Short sessions: trust the controller's own session length when disconnects
    # carry it (it also covers sessions that began with a roam). Otherwise pair
    # connect -> disconnect per AP, which misses roam-started sessions.
    durations = [d["duration_s"] for d in disconnects if d["duration_s"] is not None]
    if durations:
        short = sum(1 for d in durations if d < short_s)
    else:
        open_at: dict[str, int] = {}
        short = 0
        for e in ev:
            if e["kind"] == "connect":
                open_at[e["ap"]] = e["ts"]
            elif e["kind"] == "disconnect" and e["ap"] in open_at:
                if e["ts"] - open_at.pop(e["ap"]) < short_s:
                    short += 1

    sigs = [e["signal"] for e in ev if e["signal"] is not None]
    pairs = Counter(
        tuple(sorted((r["ap_from"], r["ap"])))
        for r in roams
        if r["ap_from"] and r["ap"]
    )
    main_pair = None
    if pairs:
        (a, b), n = pairs.most_common(1)[0]
        main_pair = {"aps": [a, b], "roams": n}

    aps = {e["ap"] for e in ev if e["ap"]} | {e["ap_from"] for e in ev if e["ap_from"]}
    m = {
        "drops": len(disconnects),
        "flaps": flaps,
        "roams": len(roams),
        "band_flips": sum(1 for r in roams if _band_flip(r)),
        "ping_pong": ping_pong,
        "bad_roams": sum(1 for r in roams if _to_weaker(r)),
        "weak_events": sum(1 for s in sigs if s <= weak_dbm),
        "min_dbm": min(sigs) if sigs else None,
        "avg_dbm": round(sum(sigs) / len(sigs)) if sigs else None,
        "short_sessions": short,
        "auth_failures": sum(1 for e in ev if e["kind"] == "fail"),
        "aps": len(aps),
    }
    return {"metrics": m, "main_ap_pair": main_pair}


def _score(m: dict[str, Any]) -> float:
    return round(
        WEIGHTS["auth_failures"] * m["auth_failures"]
        + WEIGHTS["ping_pong"] * m["ping_pong"]
        + WEIGHTS["flaps"] * m["flaps"]
        + WEIGHTS["drops"] * m["drops"]
        + WEIGHTS["short_sessions"] * m["short_sessions"]
        + WEIGHTS["weak_events"] * m["weak_events"]
        + WEIGHTS["roams"] * m["roams"],
        1,
    )


def roam_pairs(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Busiest AP pairs, both directions folded together (ping-pong shows as a high total)."""
    agg: dict[tuple[str, str], Counter] = defaultdict(Counter)
    for e in events:
        if e["kind"] != "roam" or not e["ap_from"] or not e["ap"]:
            continue
        c = agg[tuple(sorted((e["ap_from"], e["ap"])))]
        c["roams"] += 1
        c["band_flips"] += _band_flip(e)
        c["to_weaker_signal"] += _to_weaker(e)
    rows = [{"aps": list(k), **dict(v)} for k, v in agg.items()]
    for r in rows:
        r.setdefault("band_flips", 0)
        r.setdefault("to_weaker_signal", 0)
    return sorted(rows, key=lambda r: -r["roams"])


def ap_summary(events: list[dict[str, Any]], weak_dbm: int) -> list[dict[str, Any]]:
    aps: dict[str, dict[str, Any]] = {}
    for e in events:
        if not e["ap"]:
            continue
        a = aps.setdefault(
            e["ap"],
            {
                "events": 0,
                "weak_events": 0,
                "channels": Counter(),
                "util": [],
                "intf": [],
            },
        )
        a["events"] += 1
        if e["signal"] is not None and e["signal"] <= weak_dbm:
            a["weak_events"] += 1
        if e["channel"]:
            a["channels"][e["channel"]] += 1
        if e["kind"] == "disconnect":
            if e["utilization"] is not None:
                a["util"].append(e["utilization"])
            if e["interference"] is not None:
                a["intf"].append(e["interference"])

    def avg(v: list[int]) -> float | None:
        return round(sum(v) / len(v)) if v else None

    rows = [
        {
            "ap": name,
            "events": a["events"],
            "weak_events": a["weak_events"],
            "channels": dict(a["channels"].most_common(3)),
            # Load/interference are only sampled on disconnect events.
            "avg_utilization_pct": avg(a["util"]),
            "avg_interference_pct": avg(a["intf"]),
            "load_samples": len(a["util"]),
        }
        for name, a in aps.items()
    ]
    return sorted(rows, key=lambda r: (-r["weak_events"], -r["events"]))


def timeline(
    events: list[dict[str, Any]], bucket_minutes: int, weak_dbm: int
) -> list[dict[str, Any]]:
    size = bucket_minutes * 60
    buckets: dict[int, Counter] = defaultdict(Counter)
    for e in events:
        c = buckets[e["ts"] // size * size]
        c["events"] += 1
        c[e["kind"] + "s"] += 1
        c["weak_events"] += e["signal"] is not None and e["signal"] <= weak_dbm
    return [
        {
            "start_ts": start,
            "start": _iso(start),
            "events": c["events"],
            "roams": c["roams"],
            "disconnects": c["disconnects"],
            "weak_events": c["weak_events"],
        }
        for start, c in sorted(buckets.items())
    ]


def analyse(
    rows: list[dict[str, Any]],
    identities: dict[str, str] | None = None,
    *,
    subnet: str | None = None,
    identity_contains: str | None = None,
    include_iot: bool = False,
    max_clients: int = 50,
    select: list[str] | None = None,
    trail_limit: int = 100,
    bucket_minutes: int = 30,
    weak_dbm: int = -80,
    flap_minutes: int = 3,
    pingpong_minutes: int = 15,
    short_session_minutes: int = 2,
) -> dict[str, Any]:
    """Build the full report from raw ``list_events`` rows.

    ``subnet`` (CIDR) selects clients by IP: with 802.1X dynamic VLANs the
    events report the WLAN's base network, so the client IP is the reliable
    VLAN signal. ``identity_contains`` selects by 802.1X identity substring.

    ``select`` picks specific clients (a MAC, an IP, or part of an identity).
    Selected clients get their chronological event trail under ``events``, are
    not cut by ``max_clients``, and the AP / pair / timeline tables are built
    from their events only. Selectors that matched nothing are listed under
    ``unmatched_selectors``.
    """
    identities = {k.lower(): v for k, v in (identities or {}).items()}
    net = ipaddress.ip_network(subnet, strict=False) if subnet else None
    iot = re.compile(IOT_HOSTNAMES, re.I)
    id_f = identity_contains.lower() if identity_contains else None

    by_mac: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in parse_events(rows):
        by_mac[e["mac"]].append(e)

    skipped: Counter = Counter()
    kept: dict[str, list[dict[str, Any]]] = {}
    for mac, ev in by_mac.items():
        host = next((e["hostname"] for e in reversed(ev) if e["hostname"]), "")
        ip = next((e["ip"] for e in reversed(ev) if e["ip"]), None)
        identity = identities.get(mac)
        if not include_iot and iot.search(host):
            skipped["iot_hostname"] += 1
        elif net is not None and not _in_net(ip, net):
            skipped["outside_subnet_or_no_ip"] += 1
        elif id_f is not None and (not identity or id_f not in identity.lower()):
            skipped["identity_filter"] += 1
        else:
            kept[mac] = ev

    unmatched: list[str] = []
    if select:
        sels = [x.strip().lower() for x in select if x and x.strip()]
        chosen: set[str] = set()
        for sel in sels:
            hit = {
                mac
                for mac, ev in kept.items()
                if sel == mac
                or sel == next((e["ip"] for e in reversed(ev) if e["ip"]), None)
                or sel in (identities.get(mac) or "").lower()
            }
            chosen |= hit
            if not hit:
                unmatched.append(sel)
        skipped["not_selected"] += len(kept) - len(chosen)
        kept = {mac: ev for mac, ev in kept.items() if mac in chosen}
        max_clients = max(len(kept), 1)

    clients = []
    for mac, ev in kept.items():
        res = _client_metrics(
            ev,
            flap_s=flap_minutes * 60,
            pingpong_s=pingpong_minutes * 60,
            short_s=short_session_minutes * 60,
            weak_dbm=weak_dbm,
        )
        m = res["metrics"]
        clients.append(
            {
                "mac": mac,
                "identity": identities.get(mac),
                "hostname": next(
                    (e["hostname"] for e in reversed(ev) if e["hostname"]), None
                ),
                "ip": next((e["ip"] for e in reversed(ev) if e["ip"]), None),
                "ssid": next((e["ssid"] for e in reversed(ev) if e["ssid"]), None),
                "score": _score(m),
                **res,
                "first_ts": ev[0]["ts"],
                "last_ts": ev[-1]["ts"],
                "first": _iso(ev[0]["ts"]),
                "last": _iso(ev[-1]["ts"]),
                **({"events": _trail(ev, trail_limit)} if select else {}),
            }
        )
    clients.sort(key=lambda c: (-c["score"], c["identity"] or c["mac"]))

    events = [e for ev in kept.values() for e in ev]
    roams = [e for e in events if e["kind"] == "roam"]
    flips = sum(1 for r in roams if _band_flip(r))
    notes = [
        "Scores are a heuristic of symptoms (see score_weights), not measured throughput.",
        "Times are UTC epoch seconds with ISO strings.",
        "avg_utilization_pct / avg_interference_pct are sampled at disconnect events only.",
    ]
    if events and not any(e["ap_from"] or e["signal"] is not None for e in events):
        notes.append(
            "Events carried no params (no roam APs / signal): band flips and AP pairs are unavailable."
        )
    unidentified = sum(1 for c in clients if not c["identity"])
    if unidentified:
        notes.append(f"{unidentified} client(s) have no 802.1X identity on record.")

    report = {
        "summary": {
            "clients": len(clients),
            "events": len(events),
            "roams": len(roams),
            "band_flips": flips,
            "band_flip_share": round(flips / len(roams), 2) if roams else None,
            "clients_returned": min(len(clients), max_clients),
        },
        "clients": clients[:max_clients],
        "roam_pairs": roam_pairs(events)[:20],
        "aps": ap_summary(events, weak_dbm)[:20],
        "timeline": timeline(events, bucket_minutes, weak_dbm),
        "skipped_clients": dict(skipped),
        "score_weights": WEIGHTS,
        "notes": notes,
    }
    if select:
        report["unmatched_selectors"] = unmatched
    return report


def _trail(ev: list[dict[str, Any]], limit: int) -> dict[str, Any]:
    """One client's chronological story, newest ``limit`` events (None fields
    dropped to keep it small). ``count`` is the total, ``truncated`` says the
    oldest were cut."""
    rows = []
    for e in ev[-limit:]:
        row = {
            "time": _iso(e["ts"]),
            "kind": e["kind"],
            "ap_from": e["ap_from"],
            "ap": e["ap"] or None,
            "signal": e["signal"],
            "band": e["band"],
            "prev_band": e["prev_band"] if e["kind"] == "roam" else None,
            "channel": e["channel"],
            "duration_s": e["duration_s"],
        }
        rows.append({k: v for k, v in row.items() if v is not None})
    return {"count": len(ev), "truncated": len(ev) > limit, "items": rows}


def compact(
    report: dict[str, Any], top_clients: int = 10, top_pairs: int = 3, top_aps: int = 3
) -> dict[str, Any]:
    """The small default view: a ranked table, the worst pairs / APs and the
    busiest period. Everything else stays in the full report."""

    def pair(c: dict[str, Any]) -> str | None:
        p = c["main_ap_pair"]
        return f"{p['aps'][0]} <-> {p['aps'][1]} (x{p['roams']})" if p else None

    peak = max(report["timeline"], key=lambda b: b["events"], default=None)
    return {
        "detail": "summary",
        "summary": {
            **report["summary"],
            "clients_returned": min(len(report["clients"]), top_clients),
        },
        "clients": [
            {
                "identity": c["identity"] or c["mac"],
                "mac": c["mac"],
                "ip": c["ip"],
                "score": c["score"],
                "roams": c["metrics"]["roams"],
                "band_flips": c["metrics"]["band_flips"],
                "drops": c["metrics"]["drops"],
                "weak_events": c["metrics"]["weak_events"],
                "min_dbm": c["metrics"]["min_dbm"],
                "main_ap_pair": pair(c),
            }
            for c in report["clients"][:top_clients]
        ],
        "roam_pairs": [
            {
                "aps": " <-> ".join(p["aps"]),
                "roams": p["roams"],
                "band_flips": p["band_flips"],
            }
            for p in report["roam_pairs"][:top_pairs]
        ],
        "aps": [
            {"ap": a["ap"], "events": a["events"], "weak_events": a["weak_events"]}
            for a in report["aps"][:top_aps]
        ],
        "busiest_period": peak,
        "skipped_clients": report["skipped_clients"],
        "notes": report["notes"],
        "more": (
            "detail='full' adds every metric, AP/pair tables and the timeline; "
            "clients=[mac | ip | part of identity, ...] returns full metrics and "
            "the event trail for just those clients."
        ),
    }


def _in_net(ip: str | None, net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    try:
        return bool(ip) and ipaddress.ip_address(ip) in net
    except ValueError:
        return False
