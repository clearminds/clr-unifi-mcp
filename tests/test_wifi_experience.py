"""wifi_analysis (pure) and the wifi_experience_report tool."""

from __future__ import annotations

from typing import Any

import pytest

from clr_unifi_mcp import server, wifi_analysis as wa
from tests.test_wifi_data import FakeClient, _entry, _fn

A, B, C = "aa:00:00:00:00:01", "aa:00:00:00:00:02", "aa:00:00:00:00:03"


def _n(v: Any) -> dict[str, Any]:
    return {"name": str(v)}


def row(
    ts: int,
    key: str,
    mac: str,
    *,
    ap: str = "",
    ip: str = "10.1.1.5",
    host: str = "h",
    ssid: str = "corp",
    **p: Any,
) -> dict[str, Any]:
    """A row as list_events(raw=True) returns it (timestamp in seconds)."""
    return {
        "timestamp": ts,
        "key": key,
        "mac": mac,
        "device": ap,
        "ssid": ssid,
        "params": {"CLIENT": {"id": mac, "ip": ip, "hostname": host}, **p},
    }


def roam(
    ts: int,
    mac: str,
    a: str,
    b: str,
    sig: int,
    prev: int,
    band: str,
    prev_band: str,
    **kw: Any,
):
    return row(
        ts,
        "CLIENT_ROAMED_2",
        mac,
        DEVICE_FROM={"name": a},
        DEVICE_TO={"name": b},
        SIGNAL_STRENGTH=_n(sig),
        PREVIOUS_SIGNAL_STRENGTH=_n(prev),
        RADIO_BAND=_n(band),
        PREVIOUS_RADIO_BAND=_n(prev_band),
        **kw,
    )


def conn(ts: int, mac: str, ap: str, sig: int = -60, **kw: Any):
    return row(
        ts, "CLIENT_CONNECTED_WIRELESS_2", mac, ap=ap, SIGNAL_STRENGTH=_n(sig), **kw
    )


def disc(ts: int, mac: str, ap: str, **kw: Any):
    return row(ts, "CLIENT_DISCONNECTED_WIRELESS_2", mac, ap=ap, **kw)


ROWS = [
    # A: bounces ap-6g <-> ap-5g (band flips, ping-pong), lands weaker, weak signals,
    #    reconnects to the same AP within seconds (flap) after a 10 s session
    conn(1000, A, "ap-6g", -70),
    roam(1100, A, "ap-6g", "ap-5g", -85, -70, "na", "6e"),
    roam(1200, A, "ap-5g", "ap-6g", -82, -85, "6e", "na"),
    disc(
        1210,
        A,
        "ap-6g",
        AVG_UTILIZATION=_n(40),
        AVG_INTERFERENCE=_n(20),
        DURATION={"id": "10", "name": "10s"},
    ),
    conn(1220, A, "ap-6g", -90),
    # B: calm, one good roam, different subnet
    conn(1000, B, "ap-3", -55, CLIENT={"id": B, "ip": "10.9.9.9", "hostname": "bo"}),
    roam(
        5000,
        B,
        "ap-3",
        "ap-4",
        -50,
        -60,
        "na",
        "na",
        CLIENT={"id": B, "ip": "10.9.9.9", "hostname": "bo"},
    ),
    # C: IoT noise
    conn(1000, C, "ap-5g", host="tasmota-1"),
    disc(1060, C, "ap-5g", host="tasmota-1"),
]
IDS = {A: "anna@example.eu", B: "bo@other.se"}


def test_ranks_worst_first_with_metrics():
    r = wa.analyse(ROWS, IDS)
    assert [c["identity"] for c in r["clients"]] == ["anna@example.eu", "bo@other.se"]
    a = r["clients"][0]["metrics"]
    assert (a["roams"], a["band_flips"], a["ping_pong"], a["bad_roams"]) == (2, 2, 1, 1)
    assert (
        a["weak_events"],
        a["min_dbm"],
        a["drops"],
        a["flaps"],
        a["short_sessions"],
    ) == (3, -90, 1, 1, 1)
    assert r["clients"][0]["main_ap_pair"] == {"aps": ["ap-5g", "ap-6g"], "roams": 2}
    assert r["clients"][0]["score"] > r["clients"][1]["score"]
    b = r["clients"][1]["metrics"]
    assert (b["band_flips"], b["ping_pong"], b["bad_roams"], b["weak_events"]) == (
        0,
        0,
        0,
        0,
    )


def test_summary_pairs_aps_timeline():
    r = wa.analyse(ROWS, IDS)
    assert r["summary"]["roams"] == 3 and r["summary"]["band_flips"] == 2
    assert r["summary"]["band_flip_share"] == 0.67
    pair = r["roam_pairs"][0]
    assert (
        pair["aps"],
        pair["roams"],
        pair["band_flips"],
        pair["to_weaker_signal"],
    ) == (["ap-5g", "ap-6g"], 2, 2, 1)
    ap = {x["ap"]: x for x in r["aps"]}["ap-6g"]
    assert (
        ap["avg_utilization_pct"],
        ap["avg_interference_pct"],
        ap["load_samples"],
    ) == (40, 20, 1)
    assert sum(b["events"] for b in r["timeline"]) == r["summary"]["events"]


def test_filters_and_skipped_counts():
    assert [
        c["mac"] for c in wa.analyse(ROWS, IDS, subnet="10.1.1.0/24")["clients"]
    ] == [A]
    r = wa.analyse(ROWS, IDS, identity_contains="@OTHER")
    assert [c["mac"] for c in r["clients"]] == [B]
    assert r["skipped_clients"]["identity_filter"] == 1  # A; C is dropped as IoT first
    assert wa.analyse(ROWS, IDS)["skipped_clients"] == {"iot_hostname": 1}
    assert len(wa.analyse(ROWS, IDS, include_iot=True)["clients"]) == 3
    assert (
        wa.analyse(ROWS, IDS, subnet="10.1.1.0/24", max_clients=1)["summary"][
            "clients_returned"
        ]
        == 1
    )
    # no identity on record never matches an identity filter
    assert wa.analyse(ROWS, {}, identity_contains="anna")["clients"] == []


def test_without_params_falls_back_and_says_so():
    rows = [
        {
            "timestamp": 100,
            "key": "CLIENT_CONNECTED_WIRELESS_2",
            "mac": A,
            "device": "x",
            "ssid": "s",
        },
        {
            "timestamp": 200,
            "key": "CLIENT_CONNECTED_WIRELESS_2",
            "mac": A,
            "device": "y",
            "ssid": "s",
        },
        {
            "timestamp": 300,
            "key": "CLIENT_CONNECTED_WIRELESS_2",
            "mac": A,
            "device": "x",
            "ssid": "s",
        },
    ]
    r = wa.analyse(rows)
    assert (
        r["clients"][0]["metrics"]["ping_pong"] == 1
    )  # x -> y -> x from connect order
    assert any("no params" in n for n in r["notes"])
    assert r["clients"][0]["identity"] is None and any(
        "no 802.1X identity" in n for n in r["notes"]
    )


def test_short_sessions_use_reported_duration_else_pair_events():
    # reported duration wins even when connect/disconnect pairing would say otherwise
    long_by_pairing = [
        conn(0, A, "x"),
        disc(1000, A, "x", DURATION={"id": "5", "name": "5s"}),
    ]
    assert wa.analyse(long_by_pairing)["clients"][0]["metrics"]["short_sessions"] == 1
    # no duration reported: fall back to pairing connect -> disconnect on the same AP
    paired = [
        conn(100, A, "x"),
        disc(130, A, "x"),
        conn(200, A, "x"),
        disc(900, A, "x"),
    ]
    assert wa.analyse(paired)["clients"][0]["metrics"]["short_sessions"] == 1


def test_auth_failures_and_non_client_rows():
    rows = [
        row(10, "EVT_WU_AUTH_FAILED", A),
        {"timestamp": 11, "key": "AP_CHANGED_CHANNELS", "mac": "", "device": "ap"},
        {"timestamp": 12, "key": "SOMETHING_ELSE", "mac": A},
    ]
    r = wa.analyse(rows)
    assert (
        r["summary"]["events"] == 1 and r["clients"][0]["metrics"]["auth_failures"] == 1
    )


# ---- tool-level, through the paged fake controller ----


def _raw(
    i: int, key: str, mac: str, ip: str, ssid_name: str = "corp", **p: Any
) -> dict[str, Any]:
    return _entry(
        i,
        key=key,
        mac=mac,
        WLAN={"id": "w", "name": ssid_name},
        CLIENT={"id": mac, "ip": ip, "hostname": "laptop"},
        SIGNAL_STRENGTH=_n(-85),
        **p,
    )


@pytest.fixture
def use_client(monkeypatch):
    def _use(fake: FakeClient) -> FakeClient:
        monkeypatch.setattr(server, "client", fake)
        return fake

    return _use


def test_tool_resolves_identities_and_filters(use_client):
    log = [_raw(i, "CLIENT_DISCONNECTED_WIRELESS_2", A, "10.1.1.5") for i in range(3)]
    log += [
        _raw(10 + i, "CLIENT_DISCONNECTED_WIRELESS_2", B, "10.9.9.9") for i in range(2)
    ]
    log += [
        _raw(20, "CLIENT_DISCONNECTED_WIRELESS_2", C, "10.1.1.7", ssid_name="guest")
    ]
    use_client(
        FakeClient(
            log=log,
            data={
                "rest/user": [
                    {"mac": A.upper(), "last_1x_identity": "old@example.eu"},
                    {"mac": B},
                ],
                "stat/sta": [{"mac": A, "1x_identity": "anna@example.eu"}],
            },
        )
    )
    r = _fn(server.wifi_experience_report)(ssid="CORP", subnet="10.1.1.0/24")
    assert [c["identity"] for c in r["clients"]] == [
        "anna@example.eu"
    ]  # live identity wins
    assert r["clients"][0]["drops"] == 3  # default is the compact summary view
    assert r["window"]["hours"] == 24 and r["filters"]["ssid"] == "CORP"
    assert r["skipped_clients"] == {"outside_subnet_or_no_ip": 1}
    assert (
        _fn(server.wifi_experience_report)(identity_contains="example.eu")["summary"][
            "clients"
        ]
        == 1
    )


def _many_clients_log():
    log = []
    for n in range(1, 13):  # 12 clients, each with some drops
        mac = f"aa:00:00:00:01:{n:02x}"
        for i in range(n):
            log.append(
                _raw(n * 20 + i, "CLIENT_DISCONNECTED_WIRELESS_2", mac, f"10.1.1.{n}")
            )
    return log


def _ident_data():
    return {
        "rest/user": [
            {
                "mac": f"aa:00:00:00:01:{n:02x}",
                "last_1x_identity": f"user{n}@example.eu",
            }
            for n in range(1, 13)
        ],
        "stat/sta": [],
    }


def test_default_is_compact_and_much_smaller_than_full(use_client):
    import json

    use_client(FakeClient(log=_many_clients_log(), data=_ident_data()))
    f = _fn(server.wifi_experience_report)
    small, full = f(), f(detail="full")
    assert small["detail"] == "summary" and full["detail"] == "full"
    assert len(small["clients"]) == 10 and small["summary"]["clients"] == 12
    assert small["summary"]["clients_returned"] == 10
    assert set(small["clients"][0]) == {
        "identity",
        "mac",
        "ip",
        "score",
        "roams",
        "band_flips",
        "drops",
        "weak_events",
        "min_dbm",
        "main_ap_pair",
    }
    assert "timeline" not in small and "score_weights" not in small and "more" in small
    assert len(small["roam_pairs"]) <= 3 and len(small["aps"]) <= 3
    assert len(json.dumps(small)) < len(json.dumps(full)) / 2
    # full keeps the whole structure; ranking is the same in both
    assert (
        "metrics" in full["clients"][0]
        and "timeline" in full
        and len(full["clients"]) == 12
    )
    assert [c["identity"] for c in small["clients"]] == [
        c["identity"] for c in full["clients"][:10]
    ]
    assert [c["identity"] for c in f(max_clients=3)["clients"]] == [
        "user12@example.eu",
        "user11@example.eu",
        "user10@example.eu",
    ]


def test_clients_drill_down_returns_event_trail(use_client):
    use_client(FakeClient(log=_many_clients_log(), data=_ident_data()))
    r = _fn(server.wifi_experience_report)(
        clients=["USER3@example.eu", "aa:00:00:00:01:05", "10.1.1.7", "nobody@x"],
        max_clients=1,
    )
    assert r["detail"] == "clients"
    assert sorted(c["identity"] for c in r["clients"]) == [
        "user3@example.eu",
        "user5@example.eu",
        "user7@example.eu",
    ]
    c3 = next(c for c in r["clients"] if c["identity"] == "user3@example.eu")
    assert (
        "metrics" in c3 and c3["events"]["count"] == 3 and not c3["events"]["truncated"]
    )
    item = c3["events"]["items"][0]
    assert item["kind"] == "disconnect" and "time" in item and None not in item.values()
    assert r["unmatched_selectors"] == ["nobody@x"]
    assert r["skipped_clients"]["not_selected"] == 9
    assert (
        r["summary"]["clients"] == 3
    )  # other filters/stats are for the selection only


def test_trail_keeps_newest_events_up_to_trail_limit(use_client):
    log = [_raw(i, "CLIENT_DISCONNECTED_WIRELESS_2", A, "10.1.1.5") for i in range(350)]
    use_client(
        FakeClient(
            log=log,
            data={"rest/user": [{"mac": A, "last_1x_identity": "a@example.eu"}]},
        )
    )
    f = _fn(server.wifi_experience_report)
    ev = f(clients=["a@example.eu"])["clients"][0]["events"]  # default limit 100
    assert (ev["count"], ev["truncated"], len(ev["items"])) == (350, True, 100)
    times = [i["time"] for i in ev["items"]]
    assert times == sorted(times)  # chronological
    full_ev = f(clients=["a@example.eu"], trail_limit=500)["clients"][0]["events"]
    assert (len(full_ev["items"]), full_ev["truncated"]) == (350, False)
    assert (
        ev["items"][-1] == full_ev["items"][-1]
    )  # the newest events are the ones kept


def test_tool_validates_arguments(use_client):
    use_client(FakeClient())
    f = _fn(server.wifi_experience_report)
    for bad in (
        {"hours": 0},
        {"hours": 721},
        {"max_clients": 0},
        {"bucket_minutes": 1},
        {"subnet": "nope"},
        {"detail": "huge"},
        {"trail_limit": 0},
        {"trail_limit": 501},
        {"max_scan_events": 199},
        {"max_scan_events": 100001},
    ):
        with pytest.raises(ValueError):
            f(**bad)


def _noisy_log():
    """Newest-first: 400 noise entries on another SSID, then 50 older 'corp' ones."""
    log = [
        _raw(i, "CLIENT_DISCONNECTED_WIRELESS_2", B, "10.9.9.9", ssid_name="guest")
        for i in range(400)
    ]
    log += [
        _raw(400 + i, "CLIENT_DISCONNECTED_WIRELESS_2", A, "10.1.1.5")
        for i in range(50)
    ]
    return log


def _noisy_client():
    return FakeClient(
        log=_noisy_log(),
        data={"rest/user": [{"mac": A, "last_1x_identity": "a@example.eu"}]},
    )


def test_short_scan_reports_incomplete_window_not_silent_truncation(use_client):
    use_client(_noisy_client())
    r = _fn(server.wifi_experience_report)(ssid="corp", max_scan_events=200)
    w = r["window"]  # the matches are further back than one page
    assert (w["complete"], w["scanned_events"], w["events_matched"]) == (False, 200, 0)
    assert w["oldest_scanned"].startswith("2026-")
    assert (
        r["notes"][0].startswith("INCOMPLETE WINDOW") and "scan limit" in r["notes"][0]
    )
    assert r["summary"]["clients"] == 0


def test_full_scan_is_complete_and_finds_older_matches(use_client):
    use_client(_noisy_client())
    r = _fn(server.wifi_experience_report)(ssid="corp", max_scan_events=1000)
    w = r["window"]
    assert (w["complete"], w["scanned_events"], w["events_matched"]) == (True, 450, 50)
    assert not any("INCOMPLETE" in n for n in r["notes"])
    assert (
        r["clients"][0]["identity"] == "a@example.eu" and r["clients"][0]["drops"] == 50
    )


def test_oldest_scanned_is_the_oldest_raw_entry_read(use_client):
    from datetime import datetime, timezone

    use_client(_noisy_client())
    r = _fn(server.wifi_experience_report)(ssid="corp", max_scan_events=200)
    oldest = datetime.fromtimestamp(
        (1_790_000_000_000 - 199 * 60_000) // 1000, tz=timezone.utc
    )
    assert r["window"]["oldest_scanned"] == oldest.isoformat()


def test_scan_time_limit_is_reported(use_client, monkeypatch):
    monkeypatch.setattr(server, "_LOG_MAX_SECONDS", -1)  # over time after one page
    use_client(_noisy_client())
    r = _fn(server.wifi_experience_report)(ssid="corp", max_scan_events=1000)
    assert r["window"]["complete"] is False and r["window"]["scanned_events"] == 200
    assert "time limit" in r["notes"][0]


def test_list_events_can_scan_deeper(use_client):
    use_client(_noisy_client())
    f = _fn(server.list_events)
    assert len(f(limit=100, ssid="corp")) == 50  # default scan covers all 450 here
    assert f(limit=100, ssid="corp", max_scan_events=200) == []  # one page: too shallow
    assert len(f(limit=100, ssid="corp", max_scan_events=1000)) == 50
    with pytest.raises(ValueError):
        f(max_scan_events=199)


def test_tool_is_registered_read_only():
    import asyncio

    tools = (
        asyncio.run(server.mcp.get_tools())
        if hasattr(server.mcp, "get_tools")
        else None
    )
    t = (
        tools["wifi_experience_report"]
        if tools
        else next(
            x
            for x in asyncio.run(server.mcp.list_tools())
            if x.name == "wifi_experience_report"
        )
    )
    assert t.annotations.readOnlyHint is True and t.annotations.destructiveHint is False
