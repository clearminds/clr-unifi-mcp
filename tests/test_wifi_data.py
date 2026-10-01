"""list_events pagination/filters and the extra list_clients / get_client fields."""

from __future__ import annotations

from typing import Any

import pytest

from clr_unifi_mcp import server


def _fn(tool: Any):
    """FastMCP 2.x wraps the function in a Tool (``.fn``); 3.x returns it as-is."""
    return getattr(tool, "fn", tool)


def _entry(
    i: int,
    key: str = "CLIENT_CONNECTED_WIRELESS_2",
    mac: str = "aa:00:00:00:00:01",
    ap: str = "ap-1",
    **params: Any,
) -> dict[str, Any]:
    return {
        "key": key,
        "timestamp": 1_790_000_000_000 - i * 60_000,
        "parameters": {
            "CLIENT": {"id": mac, "hostname": "host-" + mac[-2:]},
            "DEVICE": {"id": "dev", "name": ap},
            **params,
        },
    }


class FakeClient:
    site = "default"

    def __init__(
        self,
        log: list[dict[str, Any]] | None = None,
        data: dict[str, Any] | None = None,
    ):
        self.log = log or []
        self.data = data or {}
        self.pages: list[int] = []

    def post_data(self, endpoint: str, json: dict[str, Any]) -> list[dict[str, Any]]:
        self.pages.append(json["pageNumber"])
        size, n = json["pageSize"], json["pageNumber"]
        return self.log[n * size : (n + 1) * size]

    def get_data(self, endpoint: str, params: Any = None) -> list[dict[str, Any]]:
        return self.data.get(endpoint, [])


@pytest.fixture
def use_client(monkeypatch):
    def _use(fake: FakeClient) -> FakeClient:
        monkeypatch.setattr(server, "client", fake)
        return fake

    return _use


def test_events_paginate_past_first_page(use_client):
    fake = use_client(FakeClient(log=[_entry(i) for i in range(450)]))
    rows = _fn(server.list_events)(limit=1000, hours=24)
    assert len(rows) == 450
    assert fake.pages == [0, 1, 2]  # 200 + 200 + 50 -> short page ends the walk


def test_events_stop_at_limit_without_extra_pages(use_client):
    fake = use_client(FakeClient(log=[_entry(i) for i in range(450)]))
    assert len(_fn(server.list_events)(limit=5)) == 5
    assert fake.pages == [0]


def test_events_filters_apply_before_limit(use_client):
    log = [
        _entry(i, key="CLIENT_CONNECTED_WIRELESS_2", mac="aa:00:00:00:00:09")
        for i in range(300)
    ]
    log += [
        _entry(300 + i, key="CLIENT_ROAMED_2", mac="aa:00:00:00:00:01", ap="ap-2")
        for i in range(3)
    ]
    use_client(FakeClient(log=log))
    rows = _fn(server.list_events)(limit=10, key="roam,auth", ap="AP-2")
    assert [r["key"] for r in rows] == ["CLIENT_ROAMED_2"] * 3
    assert (
        _fn(server.list_events)(limit=10, mac="AA:00:00:00:00:01")[0]["mac"]
        == "aa:00:00:00:00:01"
    )


def test_events_ssid_extraction_filter_and_raw(use_client):
    log = [
        _entry(0, WLAN={"id": "w1", "name": "L26_x"}),
        _entry(1, SSID="L26"),
        _entry(2),
    ]
    use_client(FakeClient(log=log))
    rows = _fn(server.list_events)(limit=10)
    assert [r["ssid"] for r in rows] == ["L26_x", "L26", ""]
    assert "params" not in rows[0]
    assert [r["ssid"] for r in _fn(server.list_events)(limit=10, ssid="l26_X")] == [
        "L26_x"
    ]
    assert (
        _fn(server.list_events)(limit=1, raw=True)[0]["params"]["WLAN"]["name"]
        == "L26_x"
    )


def test_events_have_epoch_timestamp(use_client):
    use_client(FakeClient(log=[_entry(0)]))
    assert _fn(server.list_events)(limit=1)[0]["timestamp"] == 1_790_000_000


def test_alerts_still_work(use_client):
    use_client(FakeClient(log=[_entry(0, key="AP_CLIENT_PACKET_LOSS")]))
    assert _fn(server.list_alerts)(limit=5)[0]["key"] == "AP_CLIENT_PACKET_LOSS"


def _sta(mac: str, **kw: Any) -> dict[str, Any]:
    return {
        "mac": mac,
        "hostname": "h-" + mac[-2:],
        "ip": "10.0.0.1",
        "is_wired": False,
        "ap_mac": "ap:mac",
        "signal": -60,
        "vlan": 1107,
        "network": "n",
        **kw,
    }


def test_list_clients_ssid_filter_and_quality_fields(use_client):
    use_client(
        FakeClient(
            data={
                "stat/device": [{"mac": "ap:mac", "name": "ap-1"}],
                "stat/sta": [
                    _sta(
                        "aa:00:00:00:00:01",
                        essid="L26_x",
                        radio="na",
                        channel=36,
                        satisfaction=62,
                        tx_packets=1000,
                        tx_retries=125,
                        **{"1x_identity": "a@example.eu"},
                    ),
                    _sta("aa:00:00:00:00:02", essid="L26"),
                    {**_sta("aa:00:00:00:00:03"), "is_wired": True, "essid": "ignored"},
                ],
            }
        )
    )
    rows = _fn(server.list_clients)(ssid="l26_x")
    assert len(rows) == 1
    r = rows[0]
    assert (r["ssid"], r["radio"], r["channel"], r["satisfaction"]) == (
        "L26_x",
        "na",
        36,
        62,
    )
    assert r["tx_retry_pct"] == 12.5
    assert r["dot1x_identity"] == "a@example.eu"
    everyone = _fn(server.list_clients)()
    wired = next(c for c in everyone if c["type"] == "Wired")
    assert (wired["ssid"], wired["satisfaction"], wired["tx_retry_pct"]) == (
        "",
        None,
        None,
    )
    unsampled = next(c for c in everyone if c["mac"] == "aa:00:00:00:00:02")
    assert unsampled["tx_retry_pct"] is None  # no tx_packets -> unknown, not 0


def test_get_client_offline_resolves_ssid(use_client):
    use_client(
        FakeClient(
            data={
                "stat/sta": [],
                "rest/user": [
                    {"mac": "aa:00:00:00:00:01", "hostname": "mac", "wlanconf_id": "w2"}
                ],
                "rest/wlanconf": [
                    {"_id": "w1", "name": "L26"},
                    {"_id": "w2", "name": "L26_x"},
                ],
            }
        )
    )
    got = _fn(server.get_client)("aa:00:00:00:00:01")
    assert (got["online"], got["ssid"]) == (False, "L26_x")
