"""UniFi MCP Server — FastMCP tools for UniFi Network."""

import argparse
import logging
import sys
from typing import Any

from fastmcp import FastMCP

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

WRITE_TOOLS: list[str] = []


# ---------------------------------------------------------------------------
# System / Health
# ---------------------------------------------------------------------------


@mcp.tool
def unifi_get_sysinfo() -> dict[str, Any]:
    """Get UniFi controller system information.

    Returns controller version, hostname, timezone, and other system details.
    """
    data = client.get_data("stat/sysinfo")
    return data[0] if data else {}


@mcp.tool
def unifi_get_health() -> list[dict[str, Any]]:
    """Get UniFi site health status.

    Returns status for each subsystem (wan, wlan, lan, vpn) including
    client counts, adopted device counts, and overall status.
    """
    return client.get_data("stat/health")


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------


@mcp.tool
def unifi_list_devices() -> list[dict[str, Any]]:
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


@mcp.tool
def unifi_get_device(identifier: str) -> dict[str, Any]:
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


@mcp.tool
def unifi_list_clients() -> list[dict[str, Any]]:
    """List all active connected clients (wireless + wired).

    Returns each client with hostname, IP, MAC, connection type,
    AP name, signal strength, and data rates.
    """
    clients = client.get_data("stat/sta")
    result = []
    for c in clients:
        rx_rate = c.get("rx_rate", 0)
        tx_rate = c.get("tx_rate", 0)
        result.append(
            {
                "hostname": c.get("hostname")
                or c.get("name")
                or c.get("mac", "unknown"),
                "ip": c.get("ip", ""),
                "mac": c.get("mac", ""),
                "type": "Wired" if c.get("is_wired") else "WiFi",
                "ap_name": c.get("ap_name", ""),
                "signal": f"{c.get('signal', 0)} dBm"
                if not c.get("is_wired")
                else "N/A",
                "rx_mbps": rx_rate // 1000 if rx_rate else 0,
                "tx_mbps": tx_rate // 1000 if tx_rate else 0,
                "network": c.get("network", ""),
            }
        )
    return result


@mcp.tool
def unifi_get_client(identifier: str) -> dict[str, Any]:
    """Get full details for a specific connected client.

    Args:
        identifier: Hostname, IP address, or MAC address to search for.

    Returns:
        The complete client object with all fields.

    Raises:
        ValueError: If no client matches the identifier.
    """
    clients = client.get_data("stat/sta")
    id_lower = identifier.lower()
    for c in clients:
        hostname = (c.get("hostname") or c.get("name") or "").lower()
        ip = (c.get("ip") or "").lower()
        mac = (c.get("mac") or "").lower()
        if id_lower in (hostname, ip, mac) or id_lower in hostname:
            return c
    raise ValueError(f"Client not found: {identifier}")


# ---------------------------------------------------------------------------
# Alerts / Events
# ---------------------------------------------------------------------------


@mcp.tool
def unifi_list_alerts(limit: int = 20) -> list[dict[str, Any]]:
    """List recent UniFi alarms/alerts.

    Args:
        limit: Maximum number of alerts to return (default 20).

    Returns alerts sorted by most recent, with time, key, message, and device name.
    """
    alarms = client.get_data("stat/alarm")
    result = []
    for a in alarms[:limit]:
        dt = a.get("datetime", a.get("time", ""))
        result.append(
            {
                "time": dt[:16].replace("T", " ") if dt else "",
                "key": a.get("key", ""),
                "message": a.get("msg", ""),
                "device": a.get("ap_name")
                or a.get("gw_name")
                or a.get("sw_name")
                or "",
            }
        )
    return result


@mcp.tool
def unifi_list_events(limit: int = 20) -> list[dict[str, Any]]:
    """List recent UniFi events.

    Args:
        limit: Maximum number of events to return (default 20).

    Returns events sorted by most recent with time, key, and message.
    """
    events = client.get_data("stat/event")
    result = []
    for e in events[:limit]:
        dt = e.get("datetime", e.get("time", ""))
        result.append(
            {
                "time": dt[:16].replace("T", " ") if dt else "",
                "key": e.get("key", ""),
                "message": e.get("msg", ""),
                "device": e.get("ap_name")
                or e.get("gw_name")
                or e.get("sw_name")
                or "",
            }
        )
    return result


# ---------------------------------------------------------------------------
# DPI / Top Apps
# ---------------------------------------------------------------------------


@mcp.tool
def unifi_top_apps(limit: int = 10) -> list[dict[str, Any]]:
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


@mcp.tool
def unifi_client_dpi(identifier: str) -> dict[str, Any]:
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


# ---------------------------------------------------------------------------
# Networks / WLANs
# ---------------------------------------------------------------------------


@mcp.tool
def unifi_list_networks() -> list[dict[str, Any]]:
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


@mcp.tool
def unifi_list_wlans() -> list[dict[str, Any]]:
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


@mcp.tool
def unifi_list_port_forwards() -> list[dict[str, Any]]:
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


@mcp.tool
def unifi_list_firewall_rules() -> list[dict[str, Any]]:
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


@mcp.tool
def unifi_list_firewall_groups() -> list[dict[str, Any]]:
    """List firewall groups (address groups, port groups).

    Returns group name, type, and members.
    """
    return client.get_data("rest/firewallgroup")


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------


@mcp.tool
def unifi_list_routes() -> list[dict[str, Any]]:
    """List active routes on the UniFi gateway."""
    return client.get_data("stat/routing")


# ---------------------------------------------------------------------------
# Rogue APs / DynDNS
# ---------------------------------------------------------------------------


@mcp.tool
def unifi_list_rogue_aps(limit: int = 20) -> list[dict[str, Any]]:
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


@mcp.tool
def unifi_get_dyndns() -> list[dict[str, Any]]:
    """Get Dynamic DNS status."""
    return client.get_data("stat/dynamicdns")


# ---------------------------------------------------------------------------
# SNMP Audit
# ---------------------------------------------------------------------------


@mcp.tool
def unifi_check_snmp() -> dict[str, Any]:
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


@mcp.tool
def unifi_list_port_profiles() -> list[dict[str, Any]]:
    """List switch port profiles."""
    return client.get_data("rest/portconf")


@mcp.tool
def unifi_list_radius_profiles() -> list[dict[str, Any]]:
    """List RADIUS profiles."""
    return client.get_data("rest/radiusprofile")


# ---------------------------------------------------------------------------
# Dashboard (composite)
# ---------------------------------------------------------------------------


@mcp.tool
def unifi_dashboard() -> dict[str, Any]:
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
    alarms = client.get_data("stat/alarm")

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

    # Recent alarms
    recent_alarms = []
    for a in alarms[:10]:
        dt = a.get("datetime", a.get("time", ""))
        recent_alarms.append(
            {
                "time": dt[:16].replace("T", " ") if dt else "",
                "message": a.get("msg", ""),
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


def init_composite() -> FastMCP:
    """Initialize for composite mounting. Returns the FastMCP instance."""
    global client

    settings = Settings()
    creds = settings.load_credentials()

    client = UniFiClient(
        url=creds.get("url", ""),
        site=creds.get("site", "default"),
        api_key=creds.get("api_key", ""),
        username=creds.get("username", ""),
        password=creds.get("password", ""),
    )

    if settings.unifi_read_only and WRITE_TOOLS:
        for name in WRITE_TOOLS:
            mcp.remove_tool(name)

    return mcp


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
    if read_only and WRITE_TOOLS:
        for name in WRITE_TOOLS:
            mcp.remove_tool(name)
        logger.info("Read-only mode: %d write tools removed", len(WRITE_TOOLS))

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
