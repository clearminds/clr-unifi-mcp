"""UniFi MCP Server — FastMCP tools for UniFi Network."""

import argparse
import ipaddress
import logging
import sys
import time
from typing import Any

from fastmcp import FastMCP

from clr_unifi_mcp import wifi_analysis
from clr_unifi_mcp.config import Settings, configure_logging
from clr_unifi_mcp.unifi_client import UniFiClient
from clr_unifi_mcp.middleware import ToolValidationMiddleware


def parse_cli_args() -> tuple[dict[str, Any], bool | None]:
    """Parse CLI arguments for configuration overrides."""
    parser = argparse.ArgumentParser(description="UniFi MCP Server")

    parser.add_argument("--unifi-url", type=str, help="UniFi controller URL")
    parser.add_argument("--unifi-api-key", type=str, help="UniFi API key")
    parser.add_argument("--unifi-username", type=str, help="UniFi username")
    parser.add_argument("--unifi-password", type=str, help="UniFi password")
    parser.add_argument("--unifi-site", type=str, help="UniFi site name")
    parser.add_argument(
        "--transport", type=str, choices=["stdio", "http"], help="MCP transport"
    )
    parser.add_argument("--host", type=str, help="HTTP host")
    parser.add_argument("--port", type=int, help="HTTP port")
    parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Log level",
    )
    parser.add_argument(
        "--read-only",
        action="store_true",
        default=None,
        help="Run in read-only mode (hide write tools)",
    )

    args = parser.parse_args()

    overlay: dict[str, Any] = {}
    for key in [
        "unifi_url",
        "unifi_api_key",
        "unifi_username",
        "unifi_password",
        "unifi_site",
        "transport",
        "host",
        "port",
        "log_level",
    ]:
        val = getattr(args, key, None)
        if val is not None:
            overlay[key] = val

    return overlay, args.read_only


mcp = FastMCP("UniFi")
mcp.add_middleware(ToolValidationMiddleware())
client: UniFiClient | None = None

# Imported here (not at the top) on purpose: annotations.py needs ``mcp`` from
# this module, so importing it before the ``mcp = FastMCP(...)`` line above
# would be a circular import. Do not move.
from clr_unifi_mcp.annotations import read_tool, remove_non_read_tools  # noqa: E402


# ---------------------------------------------------------------------------
# System / Health
# ---------------------------------------------------------------------------


@read_tool
def get_sysinfo() -> dict[str, Any]:
    """Get UniFi controller system information.

    Returns controller version, hostname, timezone, and other system details.
    """
    data = client.get_data("stat/sysinfo")
    return data[0] if data else {}


@read_tool
def get_health() -> list[dict[str, Any]]:
    """Get UniFi site health status.

    Returns status for each subsystem (wan, wlan, lan, vpn) including
    client counts, adopted device counts, and overall status.
    """
    return client.get_data("stat/health")


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------


@read_tool
def list_devices() -> list[dict[str, Any]]:
    """List all UniFi devices (APs, switches, gateways).

    Returns each device with name, model, IP, state, uptime (hours),
    and connected client count.
    """
    devices = client.get_data("stat/device")
    result = []
    for d in devices:
        uptime = d.get("uptime")
        uptime_str = f"{uptime // 3600}h" if uptime else "N/A"
        result.append(
            {
                "name": d.get("name") or d.get("mac", "unknown"),
                "model": d.get("model", ""),
                "ip": d.get("ip", ""),
                "mac": d.get("mac", ""),
                "type": d.get("type", ""),
                "state": "UP" if d.get("state") == 1 else "DOWN",
                "uptime": uptime_str,
                "clients": d.get("num_sta", 0),
                "version": d.get("version", ""),
            }
        )
    return result


@read_tool
def get_device(identifier: str) -> dict[str, Any]:
    """Get full details for a specific UniFi device.

    Args:
        identifier: Device name or MAC address to search for.

    Returns:
        The complete device object with all fields.

    Raises:
        ValueError: If no device matches the identifier.
    """
    devices = client.get_data("stat/device")
    id_lower = identifier.lower()
    for d in devices:
        name = (d.get("name") or "").lower()
        mac = (d.get("mac") or "").lower()
        if id_lower == name or id_lower == mac or id_lower in name:
            return d
    raise ValueError(f"Device not found: {identifier}")


# ---------------------------------------------------------------------------
# Clients
# ---------------------------------------------------------------------------


@read_tool
def list_clients(
    network: str | None = None,
    vlan_id: int | None = None,
    mac: str | None = None,
    hostname: str | None = None,
    ip: str | None = None,
    ap: str | None = None,
    ssid: str | None = None,
) -> list[dict[str, Any]]:
    """List active connected clients (wireless + wired), optionally filtered.

    Returns each client with hostname, IP, MAC, connection type, AP name,
    AP MAC, signal strength, data rates, network name, VLAN ID, and the
    802.1X identity (username) for dot1x-authenticated connections, when
    there is one. Wireless clients also carry the SSID, radio band, channel,
    the controller's satisfaction score (0-100) and the TX retry percentage;
    these are None/"" for wired clients or when the controller reports none.

    Args:
        network: Case-insensitive substring match against the network name
            (e.g. "Tenants", or the full "{nn-14} L26 Tenants").
        vlan_id: Exact VLAN ID match (e.g. 2000). Use this instead of
            `network` when you already know the VLAN and want to skip
            fetching the full, unfiltered client list.
        mac: Exact MAC address match, case-insensitive.
        hostname: Case-insensitive substring match against hostname.
        ip: Exact IP address match.
        ap: Case-insensitive substring match against the AP's name or MAC
            (wireless clients only).
        ssid: Case-insensitive exact SSID match (wireless clients only),
            e.g. "L26_x". With 802.1X dynamic VLANs the SSID is the reliable
            way to pick out a Wi-Fi network; ``network``/``vlan_id`` follow
            the VLAN the user was placed on.

    All filters are ANDed together when more than one is given.
    """
    clients = client.get_data("stat/sta")

    # Raw client objects carry ap_mac (not a name) -- joined against
    # stat/device (same data list_devices already uses) to resolve it.
    # vlan, by contrast, is already a plain field on the client object, no
    # join against rest/networkconf needed.
    ap_names = {
        d.get("mac", "").lower(): d.get("name") or d.get("mac", "")
        for d in client.get_data("stat/device")
    }

    network_f = network.lower() if network else None
    mac_f = mac.lower() if mac else None
    hostname_f = hostname.lower() if hostname else None
    ap_f = ap.lower() if ap else None
    ssid_f = ssid.lower() if ssid else None

    result = []
    for c in clients:
        rx_rate = c.get("rx_rate", 0)
        tx_rate = c.get("tx_rate", 0)
        is_wired = c.get("is_wired")
        c_hostname = c.get("hostname") or c.get("name") or c.get("mac", "unknown")
        c_mac = c.get("mac", "")
        c_ip = c.get("ip", "")
        c_network = c.get("network", "")
        c_vlan = c.get("vlan", "")
        c_ap_mac = c.get("ap_mac", "")
        c_ap_name = ap_names.get(c_ap_mac.lower(), "") if not is_wired else ""
        # last_1x_identity persists briefly after a dot1x client drops off,
        # so prefer the live field but fall back to it rather than go blank.
        c_dot1x = c.get("1x_identity") or c.get("last_1x_identity") or ""

        if network_f and network_f not in c_network.lower():
            continue
        if vlan_id is not None and str(c_vlan) != str(vlan_id):
            continue
        if mac_f and mac_f != c_mac.lower():
            continue
        if hostname_f and hostname_f not in c_hostname.lower():
            continue
        if ip and ip != c_ip:
            continue
        if ap_f and ap_f not in c_ap_name.lower() and ap_f not in c_ap_mac.lower():
            continue
        c_ssid = "" if is_wired else c.get("essid", "")
        if ssid_f and c_ssid.lower() != ssid_f:
            continue
        tx_packets = c.get("tx_packets") or 0
        tx_retry_pct = (
            round(100 * (c.get("tx_retries") or 0) / tx_packets, 1)
            if tx_packets and not is_wired
            else None
        )

        result.append(
            {
                "hostname": c_hostname,
                "ip": c_ip,
                "mac": c_mac,
                "type": "Wired" if is_wired else "WiFi",
                "ap_name": c_ap_name,
                "ap_mac": c_ap_mac if not is_wired else "",
                "signal": f"{c.get('signal', 0)} dBm" if not is_wired else "N/A",
                "rx_mbps": rx_rate // 1000 if rx_rate else 0,
                "tx_mbps": tx_rate // 1000 if tx_rate else 0,
                "network": c_network,
                "vlan_id": c_vlan,
                "dot1x_identity": c_dot1x,
                "ssid": c_ssid,
                "radio": "" if is_wired else c.get("radio", ""),
                "channel": None if is_wired else c.get("channel"),
                "satisfaction": None if is_wired else c.get("satisfaction"),
                "tx_retry_pct": tx_retry_pct,
            }
        )
    return result


def _find_client(identifier: str, endpoint: str) -> dict[str, Any] | None:
    id_lower = identifier.lower()
    for c in client.get_data(endpoint):
        hostname = (c.get("hostname") or c.get("name") or "").lower()
        ip = (c.get("ip") or c.get("last_ip") or "").lower()
        mac = (c.get("mac") or "").lower()
        if id_lower in (hostname, ip, mac) or id_lower in hostname:
            return c
    return None


@read_tool
def get_client(identifier: str) -> dict[str, Any]:
    """Get full details for a specific client -- connected now, or recently
    seen but currently offline.

    Args:
        identifier: Hostname, IP address, or MAC address to search for.

    Returns:
        The complete client object. A currently-connected client's object
        (from stat/sta) has live fields like signal/rx_bytes; an offline
        client's (from rest/user) has "online": false plus its last-known
        state (last_ip, disconnect_timestamp, last_1x_identity, etc.) --
        UniFi keeps per-client history there even while disconnected -- and
        "ssid", the name of the WLAN it last used ("" if unknown).

    Raises:
        ValueError: If no client, online or previously known, matches.
    """
    found = _find_client(identifier, "stat/sta")
    if found is not None:
        return found
    found = _find_client(identifier, "rest/user")
    if found is not None:
        # Offline records only carry wlanconf_id; resolve it so callers get the
        # SSID the client last used without a separate list_wlans join.
        ssid = ""
        if found.get("wlanconf_id"):
            ssid = next(
                (
                    w.get("name", "")
                    for w in client.get_data("rest/wlanconf")
                    if w.get("_id") == found["wlanconf_id"]
                ),
                "",
            )
        return {**found, "online": False, "ssid": ssid}
    raise ValueError(f"Client not found: {identifier}")


# ---------------------------------------------------------------------------
# Alerts / Events
# ---------------------------------------------------------------------------


def _param_entity(entry: dict[str, Any], *names: str) -> dict[str, Any]:
    """Pull a named entity out of a system-log entry's ``parameters``.

    Confirmed live against this server's own controller: ``parameters`` is
    a flat dict whose CLIENT/DEVICE values are themselves nested objects
    (``{"id": "<mac>", "name": ..., "hostname": ..., "ip": ...}``), not
    plain strings -- there is no separate "message" field to fall back on,
    so the readable text below is built from these entities.
    """
    params = entry.get("parameters")
    if not isinstance(params, dict):
        return {}
    for name in names:
        val = params.get(name)
        if isinstance(val, dict):
            return val
        if isinstance(val, str) and val:
            return {"id": val}
    return {}


_LOG_PAGE_SIZE = 200
# Hard cap of 5000 entries per call, so a wide window can't hang the tool.
_LOG_MAX_PAGES = 25


def _param_text(params: Any, *needles: str) -> str:
    """First string value in ``params`` whose key contains any of ``needles``.

    Entity-style values ({"id": ..., "name": ...}) yield their name. The exact
    parameter keys differ between controller versions, so this matches loosely
    and ``list_events(raw=True)`` exposes the untouched ``parameters`` for
    checking what a given controller actually sends.
    """
    if not isinstance(params, dict):
        return ""
    for key, val in params.items():
        if not any(n in key.lower() for n in needles):
            continue
        if isinstance(val, str) and val:
            return val
        if isinstance(val, dict):
            text = val.get("name") or val.get("id")
            if isinstance(text, str) and text:
                return text
    return ""


def _system_log(
    category: str,
    hours: int,
    limit: int,
    mac: str | None,
    key: str | None = None,
    ap: str | None = None,
    ssid: str | None = None,
    raw: bool = False,
) -> list[dict[str, Any]]:
    """Query the v2 system-log API that replaced stat/alarm and stat/event
    on UniFi Network 10.x (the legacy endpoints now 404 there).

    Pages through the log (newest first) until ``limit`` matching entries are
    found, the log runs out, or ``_LOG_MAX_PAGES`` is reached.

    Args:
        category: Log category -- "all" (general activity) or
            "device-alert" (device-level alerts/flaps) are the ones this
            server uses; UniFi also exposes "admin-activity" and others.
        hours: How far back to look.
        limit: Max entries to return, most recent first.
        mac: Optional client MAC to filter to, matched against the entry's
            CLIENT parameter.
        key: Optional case-insensitive substring of the event key
            (e.g. "ROAM", "DISCONNECT"); several can be given comma-separated.
        ap: Optional case-insensitive substring of the device (AP) name.
        ssid: Optional case-insensitive exact SSID; entries that carry no
            SSID never match.
        raw: Include the entry's untouched ``parameters`` as ``params``.
    """
    now_ms = int(time.time() * 1000)
    mac_l = mac.lower() if mac else None
    keys_l = [k.strip().lower() for k in key.split(",") if k.strip()] if key else []
    ap_l = ap.lower() if ap else None
    ssid_l = ssid.lower() if ssid else None
    url = f"/proxy/network/v2/api/site/{client.site}/system-log/{category}"

    result: list[dict[str, Any]] = []
    for page in range(_LOG_MAX_PAGES):
        body = {
            "timestampFrom": now_ms - hours * 3600 * 1000,
            "timestampTo": now_ms,
            "pageSize": _LOG_PAGE_SIZE,
            "pageNumber": page,
        }
        entries = client.post_data(url, json=body)
        if not entries:
            break
        for e in entries:
            params = e.get("parameters")
            client_entity = _param_entity(e, "CLIENT", "MAC", "USER")
            e_mac = client_entity.get("id", "").lower()
            if mac_l and mac_l != e_mac:
                continue
            e_key = e.get("key", "")
            if keys_l and not any(k in e_key.lower() for k in keys_l):
                continue
            device_entity = _param_entity(e, "DEVICE", "AP", "SWITCH", "GW")
            device_name = device_entity.get("name", "")
            if ap_l and ap_l not in device_name.lower():
                continue
            e_ssid = _param_text(params, "ssid", "wlan")
            if ssid_l and e_ssid.lower() != ssid_l:
                continue
            client_name = (
                client_entity.get("hostname")
                or client_entity.get("name")
                or e_mac
                or ""
            )
            message = e_key.replace("_", " ").title()
            if client_name:
                message += f" -- {client_name}"
            if device_name:
                message += f" @ {device_name}"
            ts = e.get("timestamp")
            row: dict[str, Any] = {
                "time": time.strftime("%Y-%m-%d %H:%M", time.localtime(ts / 1000))
                if ts
                else "",
                # Epoch seconds: unambiguous, unlike "time" (server-local, no zone).
                "timestamp": ts // 1000 if ts else None,
                "key": e_key,
                "message": message,
                "device": device_name,
                "mac": e_mac,
                "ssid": e_ssid,
            }
            if raw:
                row["params"] = params
            result.append(row)
            if len(result) >= limit:
                return result
        if len(entries) < _LOG_PAGE_SIZE:
            break
    return result


@read_tool
def list_alerts(limit: int = 20, hours: int = 24) -> list[dict[str, Any]]:
    """List recent UniFi device alerts (port flaps, device issues, etc.).

    Args:
        limit: Maximum number of alerts to return (default 20).
        hours: How many hours back to search (default 24).

    Returns alerts sorted by most recent, with time, key, message, device, and mac.
    """
    return _system_log("device-alert", hours, limit, None)


@read_tool
def list_events(
    limit: int = 20,
    hours: int = 24,
    mac: str | None = None,
    key: str | None = None,
    ap: str | None = None,
    ssid: str | None = None,
    raw: bool = False,
) -> list[dict[str, Any]]:
    """List recent UniFi events -- connects, disconnects, roams, auth failures, etc.

    Pages through the whole window, so a large ``limit`` really reaches back
    ``hours`` (capped at 5000 entries per call). Filters are applied
    server-side before ``limit``, which makes them the way to dig through a
    noisy site (e.g. IoT devices reconnecting every few minutes).

    Args:
        limit: Maximum number of events to return (default 20).
        hours: How many hours back to search (default 24).
        mac: Optional client MAC to filter to -- use this to pull one
            device's connection history (roaming, drops, auth failures)
            instead of scrolling the whole site's activity log.
        key: Optional event-key substring, case-insensitive; comma-separate
            several (e.g. "ROAM,DISCONNECT" or "AUTH,RADIUS").
        ap: Optional substring of the AP name the event happened on.
        ssid: Optional exact SSID. Only events whose log entry carries an SSID
            can match -- use ``raw=True`` to see whether your controller
            includes one.
        raw: Include each entry's untouched ``parameters`` as ``params``.

    Returns events sorted by most recent with time, timestamp (epoch seconds),
    key, message, device, mac and ssid ("" when the entry has none).
    """
    return _system_log("all", hours, limit, mac, key=key, ap=ap, ssid=ssid, raw=raw)


def _dot1x_identities() -> dict[str, str]:
    """MAC -> 802.1X identity, from every client the controller knows.

    ``rest/user`` keeps ``last_1x_identity`` for clients that have left;
    ``stat/sta`` has the live ``1x_identity`` and wins when both exist.
    """
    ids: dict[str, str] = {}
    for c in client.get_data("rest/user"):
        ident = c.get("last_1x_identity")
        if ident and c.get("mac"):
            ids[c["mac"].lower()] = ident
    for c in client.get_data("stat/sta"):
        ident = c.get("1x_identity") or c.get("last_1x_identity")
        if ident and c.get("mac"):
            ids[c["mac"].lower()] = ident
    return ids


@read_tool
def wifi_experience_report(
    ssid: str | None = None,
    hours: int = 24,
    subnet: str | None = None,
    identity_contains: str | None = None,
    include_iot: bool = False,
    max_clients: int | None = None,
    bucket_minutes: int = 30,
    detail: str = "summary",
    clients: list[str] | None = None,
    trail_limit: int = 100,
) -> dict[str, Any]:
    """Who had a bad Wi-Fi experience, and where: a ranked, JSON report built
    from the controller's connect / disconnect / roam events.

    Three sizes, so the common question stays cheap:
      * default (``detail="summary"``, ~3-4 KB): ranked table with the key
        numbers, the top AP pairs and APs, and the busiest period.
      * ``detail="full"`` (~16 KB for 16 clients): every metric per client,
        the AP and pair tables, the timeline, score weights.
      * ``clients=[...]``: drill into specific clients: full metrics plus their
        chronological event trail (connects, roams with AP from/to, signal,
        band). Pick them from the summary by ``mac`` or identity.

    One call replaces pulling events, looking up each client's 802.1X
    identity, and tallying by hand. Use it for "which users had the worst
    Wi-Fi today on SSID X", "is anyone ping-ponging between APs", "which AP
    pair is the problem" and per-tenant comparisons.

    Args:
        ssid: Only this SSID, exact, case-insensitive (e.g. "Corp-802.1X").
            Omit for every wireless client on the site (large, includes IoT).
        hours: Look-back window (1-720, default 24). At most 5000 events are
            read; if that cap is hit, ``notes`` says the oldest are missing --
            use a shorter window.
        subnet: Only clients whose IP is in this CIDR (e.g. "10.34.6.0/24").
            This is how to select a dynamic-VLAN tenant: the log reports the
            WLAN's base network, not the VLAN the user was actually placed on.
        identity_contains: Only clients whose 802.1X identity contains this
            text, case-insensitive (e.g. "@example.com"). Clients with no
            identity on record never match.
        include_iot: Keep tasmota/relay/esp/shelly-style devices (default off:
            they reconnect every few minutes and drown the ranking).
        max_clients: How many of the worst clients to return (default 10 for
            summary, 50 for full). Ignored with ``clients``.
        bucket_minutes: Timeline bucket size (5-240, default 30).
        detail: "summary" (default) or "full".
        clients: Specific clients to drill into: each entry is a MAC, an IP,
            or part of an 802.1X identity (e.g. ["a@example.com",
            "aa:bb:cc:dd:ee:ff"]). Returns full detail + event trail for just
            those clients; entries that match nothing are listed in
            ``unmatched_selectors``. Other filters still apply.
        trail_limit: Newest events kept in each selected client's trail
            (1-500, default 100); ``events.count`` / ``events.truncated`` say
            what was cut. A trail costs roughly 170 bytes per event.

    Returns a dict (summary shape: summary, clients rows with identity, mac,
    ip, score, roams, band_flips, drops, weak_events, min_dbm, main_ap_pair;
    roam_pairs and aps top 3; busiest_period; skipped_clients; notes). The
    full shape, also used for ``clients``:
        summary: clients, events, roams, band_flips, band_flip_share.
        clients: worst first. Each has mac, identity, hostname, ip, ssid,
            score, first/last (UTC), main_ap_pair {aps, roams} and metrics:
            drops, flaps (reconnect to the same AP within 3 min), roams,
            band_flips (e.g. 6 GHz <-> 5 GHz), ping_pong (A->B->A within
            15 min), bad_roams (landed >3 dB weaker), weak_events (<= -80
            dBm), min_dbm, avg_dbm, short_sessions (< 2 min),
            auth_failures, aps.
        roam_pairs: busiest AP pairs, both directions folded, with
            band_flips and to_weaker_signal counts. A pair where nearly
            every roam is a band flip points at coverage / band steering
            rather than at the clients.
        aps: per AP weak_events, channels, avg utilization/interference
            (sampled at disconnects only) -- worst first.
        timeline: events / roams / disconnects / weak_events per bucket.
        skipped_clients: how many clients each filter dropped.
        score_weights, notes: how the score is built and the caveats.

    Times are UTC (epoch seconds, plus ISO strings). The score is a heuristic
    of symptoms, not measured throughput: compare clients within one report.
    """
    if not 1 <= hours <= 720:
        raise ValueError("hours must be between 1 and 720")
    if detail not in ("summary", "full"):
        raise ValueError('detail must be "summary" or "full"')
    if not 1 <= trail_limit <= 500:
        raise ValueError("trail_limit must be between 1 and 500")
    if max_clients is not None and not 1 <= max_clients <= 500:
        raise ValueError("max_clients must be between 1 and 500")
    if not 5 <= bucket_minutes <= 240:
        raise ValueError("bucket_minutes must be between 5 and 240")
    if subnet:
        try:
            ipaddress.ip_network(subnet, strict=False)
        except ValueError as e:
            raise ValueError(f"subnet must be a CIDR such as 10.0.0.0/24: {e}") from e

    rows = _system_log(
        "all", hours, _LOG_MAX_PAGES * _LOG_PAGE_SIZE, None, ssid=ssid, raw=True
    )
    report = wifi_analysis.analyse(
        rows,
        _dot1x_identities(),
        subnet=subnet,
        identity_contains=identity_contains,
        include_iot=include_iot,
        max_clients=max_clients or (50 if detail == "full" else 500),
        select=clients,
        trail_limit=trail_limit,
        bucket_minutes=bucket_minutes,
    )
    if clients:
        report["detail"] = "clients"
    elif detail == "summary":
        report = wifi_analysis.compact(report, top_clients=max_clients or 10)
    else:
        report["detail"] = "full"
    report["window"] = {"hours": hours, "timezone": "UTC", "events_fetched": len(rows)}
    report["filters"] = {
        "ssid": ssid,
        "subnet": subnet,
        "identity_contains": identity_contains,
        "include_iot": include_iot,
    }
    if len(rows) >= _LOG_MAX_PAGES * _LOG_PAGE_SIZE:
        report["notes"].append(
            f"Event cap ({len(rows)}) reached: the window is truncated, oldest events missing. "
            "Use a shorter window."
        )
    return report


# ---------------------------------------------------------------------------
# DPI / Top Apps
# ---------------------------------------------------------------------------


@read_tool
def top_apps(limit: int = 10) -> list[dict[str, Any]]:
    """Get top applications by bandwidth usage (DPI data).

    Args:
        limit: Number of top apps to return (default 10).

    Returns apps sorted by total traffic (rx + tx) in GB.
    """
    data = client.get_data("stat/sitedpi")
    if not data:
        return []

    apps = data[0].get("by_app", [])
    apps.sort(key=lambda a: -(a.get("tx_bytes", 0) + a.get("rx_bytes", 0)))

    result = []
    for a in apps[:limit]:
        rx_gb = round(a.get("rx_bytes", 0) / 1073741824, 2)
        tx_gb = round(a.get("tx_bytes", 0) / 1073741824, 2)
        result.append(
            {
                "app": a.get("app", ""),
                "category": a.get("cat", ""),
                "rx_gb": rx_gb,
                "tx_gb": tx_gb,
                "total_gb": round(rx_gb + tx_gb, 2),
            }
        )
    return result


@read_tool
def client_dpi(identifier: str) -> dict[str, Any]:
    """Get per-client DPI (Deep Packet Inspection) bandwidth stats.

    Args:
        identifier: Client MAC address.

    Returns:
        App-level traffic breakdown for the client.

    Raises:
        ValueError: If no DPI data exists for the given MAC address.
    """
    data = client.get_data("stat/stadpi")
    id_lower = identifier.lower()
    for entry in data:
        if (entry.get("mac") or "").lower() == id_lower:
            return entry
    raise ValueError(f"No DPI data for client: {identifier}")


@read_tool
def get_client_history(
    mac: str, interval: str = "hourly", hours: int = 24
) -> list[dict[str, Any]]:
    """Get one client's bandwidth history -- per-period RX/TX traffic over time.

    Verified live against our own controller: stat/report/{interval}.user
    takes "mac" as a single string (not a list), and start/end as epoch
    milliseconds -- the two things sources disagree on elsewhere.

    Args:
        mac: Client MAC address (exact match).
        interval: "5minutes", "hourly", or "daily". Use "hourly" for a day
            or two of detail, "daily" for a longer trend (set hours
            accordingly, e.g. 168 for a week of daily buckets).
        hours: How far back to look, regardless of interval (default 24).

    Returns periods oldest-first, each with time, rx_gb, tx_gb, and total_gb.

    Raises:
        ValueError: If interval isn't one of "5minutes", "hourly", "daily".
    """
    if interval not in ("5minutes", "hourly", "daily"):
        raise ValueError(
            f'interval must be "5minutes", "hourly", or "daily", got {interval!r}'
        )
    now_ms = int(time.time() * 1000)
    body = {
        "attrs": ["bytes", "rx_bytes", "tx_bytes", "time"],
        "start": now_ms - hours * 3600 * 1000,
        "end": now_ms,
        "mac": mac,
    }
    periods = client.post_data(f"stat/report/{interval}.user", json=body)
    result = []
    for p in periods:
        ts = p.get("time")
        rx_gb = round(p.get("rx_bytes", 0) / 1073741824, 3)
        tx_gb = round(p.get("tx_bytes", 0) / 1073741824, 3)
        result.append(
            {
                "time": time.strftime("%Y-%m-%d %H:%M", time.localtime(ts / 1000))
                if ts
                else "",
                "rx_gb": rx_gb,
                "tx_gb": tx_gb,
                "total_gb": round(rx_gb + tx_gb, 3),
            }
        )
    return result


# ---------------------------------------------------------------------------
# Networks / WLANs
# ---------------------------------------------------------------------------


@read_tool
def list_networks() -> list[dict[str, Any]]:
    """List all configured networks (VLANs, subnets).

    Returns network name, VLAN ID, subnet, purpose, DHCP status,
    and domain name.
    """
    networks = client.get_data("rest/networkconf")
    result = []
    for n in networks:
        result.append(
            {
                "name": n.get("name", ""),
                "vlan_id": n.get("vlan", ""),
                "subnet": n.get("ip_subnet", ""),
                "purpose": n.get("purpose", ""),
                "dhcp_enabled": n.get("dhcpd_enabled", False),
                "domain_name": n.get("domain_name", ""),
                "_id": n.get("_id", ""),
            }
        )
    return result


@read_tool
def list_wlans() -> list[dict[str, Any]]:
    """List all configured WLANs/SSIDs.

    Returns SSID name, enabled status, security mode, band, and VLAN.
    """
    wlans = client.get_data("rest/wlanconf")
    result = []
    for w in wlans:
        result.append(
            {
                "name": w.get("name", ""),
                "enabled": w.get("enabled", False),
                "security": w.get("security", ""),
                "wpa_mode": w.get("wpa_mode", ""),
                "band": w.get("wlan_band", ""),
                "vlan": w.get("networkconf_id", ""),
                "_id": w.get("_id", ""),
            }
        )
    return result


# ---------------------------------------------------------------------------
# Firewall / Port Forwards
# ---------------------------------------------------------------------------


@read_tool
def list_port_forwards() -> list[dict[str, Any]]:
    """List configured port forwarding rules.

    Returns rule name, enabled status, protocol, destination, and ports.
    """
    rules = client.get_data("rest/portforward")
    result = []
    for r in rules:
        result.append(
            {
                "name": r.get("name", ""),
                "enabled": r.get("enabled", False),
                "proto": r.get("proto", ""),
                "fwd": r.get("fwd", ""),
                "fwd_port": r.get("fwd_port", ""),
                "dst_port": r.get("dst_port", ""),
                "src": r.get("src", "any"),
            }
        )
    return result


@read_tool
def list_firewall_rules() -> list[dict[str, Any]]:
    """List user-configured firewall rules.

    Returns rule name, enabled status, action, protocol, and source/destination.
    """
    rules = client.get_data("rest/firewallrule")
    result = []
    for r in rules:
        result.append(
            {
                "name": r.get("name", ""),
                "enabled": r.get("enabled", False),
                "action": r.get("action", ""),
                "protocol": r.get("protocol", ""),
                "ruleset": r.get("ruleset", ""),
                "src_firewallgroup_ids": r.get("src_firewallgroup_ids", []),
                "dst_firewallgroup_ids": r.get("dst_firewallgroup_ids", []),
            }
        )
    return result


@read_tool
def list_firewall_groups() -> list[dict[str, Any]]:
    """List firewall groups (address groups, port groups).

    Returns group name, type, and members.
    """
    return client.get_data("rest/firewallgroup")


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------


@read_tool
def list_routes() -> list[dict[str, Any]]:
    """List active routes on the UniFi gateway."""
    return client.get_data("stat/routing")


# ---------------------------------------------------------------------------
# Rogue APs / DynDNS
# ---------------------------------------------------------------------------


@read_tool
def list_rogue_aps(limit: int = 20) -> list[dict[str, Any]]:
    """List detected rogue/neighboring APs.

    Args:
        limit: Maximum number of rogue APs to return (default 20).

    Returns AP BSSID, SSID, channel, signal, and last seen time.
    """
    aps = client.get_data("stat/rogueap")
    result = []
    for ap in aps[:limit]:
        result.append(
            {
                "bssid": ap.get("bssid", ""),
                "ssid": ap.get("essid", ""),
                "channel": ap.get("channel", ""),
                "signal": ap.get("rssi", ""),
                "last_seen": ap.get("last_seen", ""),
                "ap_mac": ap.get("ap_mac", ""),
            }
        )
    return result


@read_tool
def get_dyndns() -> list[dict[str, Any]]:
    """Get Dynamic DNS status."""
    return client.get_data("stat/dynamicdns")


# ---------------------------------------------------------------------------
# SNMP Audit
# ---------------------------------------------------------------------------


@read_tool
def check_snmp() -> dict[str, Any]:
    """Audit SNMP contact/location configuration on all devices.

    Returns a summary of devices with and without SNMP fields configured,
    plus a per-device breakdown.
    """
    devices = client.get_data("stat/device")
    has_snmp = 0
    missing_snmp = 0
    details = []

    for d in devices:
        name = d.get("name") or d.get("mac", "unknown")
        contact = d.get("snmp_contact", "")
        location = d.get("snmp_location", "")
        has_both = bool(contact and location)

        if has_both:
            has_snmp += 1
        else:
            missing_snmp += 1

        details.append(
            {
                "name": name,
                "mac": d.get("mac", ""),
                "snmp_contact": contact or "(missing)",
                "snmp_location": location or "(missing)",
                "configured": has_both,
            }
        )

    return {
        "total": len(devices),
        "configured": has_snmp,
        "missing": missing_snmp,
        "devices": details,
    }


# ---------------------------------------------------------------------------
# Port Profiles / Settings / RADIUS
# ---------------------------------------------------------------------------


@read_tool
def list_port_profiles() -> list[dict[str, Any]]:
    """List switch port profiles."""
    return client.get_data("rest/portconf")


@read_tool
def list_radius_profiles() -> list[dict[str, Any]]:
    """List RADIUS profiles."""
    return client.get_data("rest/radiusprofile")


# ---------------------------------------------------------------------------
# Dashboard (composite)
# ---------------------------------------------------------------------------


@read_tool
def dashboard() -> dict[str, Any]:
    """Get a comprehensive network dashboard overview.

    Returns a composite view with system info, health, device summary,
    client summary, top clients by traffic, networks, WLANs,
    port forwards, and recent alarms. Useful for a quick overview
    of the entire UniFi deployment.
    """
    sysinfo = client.get_data("stat/sysinfo")
    health = client.get_data("stat/health")
    devices = client.get_data("stat/device")
    clients = client.get_data("stat/sta")
    networks = client.get_data("rest/networkconf")
    wlans = client.get_data("rest/wlanconf")
    port_forwards = client.get_data("rest/portforward")
    recent_alarms = _system_log("device-alert", hours=24, limit=10, mac=None)

    # Device summary
    device_summary = []
    for d in devices:
        uptime = d.get("uptime")
        device_summary.append(
            {
                "name": d.get("name") or d.get("mac", "unknown"),
                "model": d.get("model", ""),
                "ip": d.get("ip", ""),
                "state": "UP" if d.get("state") == 1 else "DOWN",
                "uptime": f"{uptime // 3600}h" if uptime else "N/A",
                "clients": d.get("num_sta", 0),
            }
        )

    # Client summary
    wired = sum(1 for c in clients if c.get("is_wired"))
    wireless = len(clients) - wired

    # Top 15 clients by traffic
    clients_sorted = sorted(
        clients,
        key=lambda c: -(c.get("tx_bytes", 0) + c.get("rx_bytes", 0)),
    )
    top_clients = []
    for c in clients_sorted[:15]:
        tx_mb = round(c.get("tx_bytes", 0) / 1048576, 1)
        rx_mb = round(c.get("rx_bytes", 0) / 1048576, 1)
        top_clients.append(
            {
                "hostname": c.get("hostname") or c.get("name") or c.get("mac", ""),
                "ip": c.get("ip", ""),
                "mac": c.get("mac", ""),
                "type": "Wired" if c.get("is_wired") else "WiFi",
                "tx_mb": tx_mb,
                "rx_mb": rx_mb,
            }
        )

    # Network summary
    net_summary = []
    for n in networks:
        net_summary.append(
            {
                "name": n.get("name", ""),
                "vlan": n.get("vlan", ""),
                "subnet": n.get("ip_subnet", ""),
                "purpose": n.get("purpose", ""),
                "dhcp": n.get("dhcpd_enabled", False),
            }
        )

    # WLAN summary
    wlan_summary = []
    for w in wlans:
        wlan_summary.append(
            {
                "ssid": w.get("name", ""),
                "enabled": w.get("enabled", False),
                "security": w.get("security", ""),
                "band": w.get("wlan_band", ""),
            }
        )

    # Port forward summary
    pf_summary = []
    for p in port_forwards:
        pf_summary.append(
            {
                "name": p.get("name", ""),
                "enabled": p.get("enabled", False),
                "proto": p.get("proto", ""),
                "fwd": f"{p.get('fwd', '')}:{p.get('fwd_port', '')}",
                "dst_port": p.get("dst_port", ""),
            }
        )

    return {
        "sysinfo": sysinfo[0] if sysinfo else {},
        "health": health,
        "devices": device_summary,
        "clients": {
            "total": len(clients),
            "wired": wired,
            "wireless": wireless,
            "top_by_traffic": top_clients,
        },
        "networks": net_summary,
        "wlans": wlan_summary,
        "port_forwards": pf_summary,
        "recent_alarms": recent_alarms,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    """Main entry point for the UniFi MCP server."""
    global client

    cli_overlay, cli_read_only = parse_cli_args()

    try:
        settings = Settings(**cli_overlay)
    except Exception as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(1)

    configure_logging(settings.log_level)
    logger = logging.getLogger(__name__)

    creds = settings.load_credentials()

    logger.info("Starting UniFi MCP Server")
    logger.info(
        "Config: url=%s site=%s auth=%s transport=%s",
        creds.get("url", ""),
        creds.get("site", "default"),
        "api_key" if creds.get("api_key") else "password",
        settings.transport,
    )

    try:
        client = UniFiClient(
            url=creds.get("url", ""),
            site=creds.get("site", "default"),
            api_key=creds.get("api_key", ""),
            username=creds.get("username", ""),
            password=creds.get("password", ""),
        )
        logger.debug("UniFi client initialized")
    except Exception as e:
        logger.error("Failed to initialize UniFi client: %s", e)
        sys.exit(1)

    read_only = cli_read_only if cli_read_only is not None else settings.unifi_read_only
    if read_only:
        removed = remove_non_read_tools(mcp)
        logger.info("Read-only mode: %d non-read tools removed", removed)

    try:
        if settings.transport == "stdio":
            logger.info("Starting stdio transport")
            mcp.run(transport="stdio")
        elif settings.transport == "http":
            logger.info(
                "Starting HTTP transport on %s:%s", settings.host, settings.port
            )
            mcp.run(transport="http", host=settings.host, port=settings.port)
    except Exception as e:
        logger.error("Failed to start MCP server: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
