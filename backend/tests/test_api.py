"""HTTP API on a scanned catalog: search, protocols, scan config, exports."""

import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import routes.scan as scan_routes
from conftest import requires_tshark, run_scan
from routes.exports import router as exports_router
from routes.protocols import router as protocols_router
from routes.scan import router as scan_router
from routes.search import router as search_router
from services.scan import ScanState, get_scan_service

pytestmark = requires_tshark


@pytest.fixture
def client(ctx, sample_pcaps):
    """The API routers on a catalog holding sip.pcap, dns.pcap and mixed.pcap.

    main.py is not imported: its startup would connect to the real Redis and
    start the hourly scan loop.
    """
    run_scan(ctx)
    app = FastAPI()
    for router in (search_router, protocols_router, scan_router, exports_router):
        app.include_router(router)
    return TestClient(app)


def names(client, query, **params):
    body = client.get("/search", params={"protocol": query, "limit": 100, **params}).json()
    return sorted(f["filename"] for f in body["data"]), body


# --- search ---

@pytest.mark.parametrize("query, expected", [
    ("sip", ["mixed.pcap", "sip.pcap"]),
    ("sip dns", ["mixed.pcap"]),
    ("sip !dns", ["sip.pcap"]),
    ("sip|dns", ["dns.pcap", "mixed.pcap", "sip.pcap"]),
    ("name:mixed", ["mixed.pcap"]),
    ("udp !name:mixed", ["dns.pcap", "sip.pcap"]),
    ("", ["dns.pcap", "mixed.pcap", "sip.pcap"]),
])
def test_search(client, query, expected):
    assert names(client, query)[0] == expected


def test_search_reports_how_it_read_the_query(client):
    _, body = names(client, "sip !dns")
    assert body["query"]["all"] == ["sip"] and body["query"]["none"] == ["dns"]
    assert body["data"][0]["matched_protocols"] == ["sip"]


def test_search_facets_count_files_in_the_result(client):
    _, body = names(client, "udp")
    facets = {f["protocol"]: f["files"] for f in body["facets"]}
    assert facets["udp"] == 3 and facets["sip"] == 2 and facets["dns"] == 2


def test_typo_gets_a_suggestion(client):
    found, body = names(client, "siip")
    assert found == [] and "sip" in body["suggestions"]


def test_sort_and_pagination(client):
    body = client.get("/search", params={"sort_by": "size_bytes", "descending": True, "limit": 1, "page": 1}).json()
    assert body["total"] == 3 and body["data"][0]["filename"] == "sip.pcap"   # 3 SIP packets: the largest
    page3 = client.get("/search", params={"sort_by": "size_bytes", "descending": True, "limit": 1, "page": 3}).json()
    assert page3["data"][0]["filename"] == "dns.pcap"


def test_protocols_lists_file_counts(client):
    rows = {r["protocol"]: r["files"] for r in client.get("/protocols").json()}
    assert rows["sip"] == 2 and rows["dns"] == 2 and rows["udp"] == 3


# --- scan config ---

def test_change_scan_mode(client, ctx, monkeypatch):
    monkeypatch.setattr(scan_routes, "save_scan_mode", lambda mode: True)   # never write the real config.yaml
    res = client.put("/scan-config", json={"scan_mode": "quick"})
    assert res.status_code == 200 and res.json()["scan_mode"] == "quick"
    assert ctx.config.pcap.scan_mode == "quick"
    assert client.put("/scan-config", json={"scan_mode": "turbo"}).status_code == 422


def test_scan_mode_is_locked_while_scanning(client):
    get_scan_service().scan_status["state"] = ScanState.RUNNING
    assert client.put("/scan-config", json={"scan_mode": "full"}).status_code == 409


# --- exports ---

def file_hash(client, name):
    return client.get("/search", params={"protocol": f"name:{name}"}).json()["data"][0]["hash"]


def wait_for(client, job, timeout=30):
    deadline = time.time() + timeout
    while job["state"] in ("queued", "running") and time.time() < deadline:
        time.sleep(0.2)
        job = client.get(f"/exports/{job['id']}").json()
    return job


def test_export_extracts_matching_packets_and_caches(client):
    h = file_hash(client, "mixed")
    job = wait_for(client, client.post("/exports", json={"file_hash": h, "filter": "sip"}).json())
    assert job["state"] == "ready" and job["packets"] == 1 and job["cached"] is False

    res = client.get(f"/exports/{job['id']}/download")
    assert res.status_code == 200
    assert res.content[:4] == bytes.fromhex("0a0d0d0a")          # pcapng magic
    assert "mixed__sip.pcapng" in res.headers["content-disposition"]

    again = client.post("/exports", json={"file_hash": h, "filter": "  sip "}).json()
    assert again["id"] == job["id"] and again["state"] == "ready" and again["cached"] is True


def test_export_with_no_matching_packet(client):
    job = client.post("/exports", json={"file_hash": file_hash(client, "dns"), "filter": "sip"}).json()
    assert wait_for(client, job)["state"] == "empty"


def test_export_rejects_bad_filter_and_unknown_file(client):
    h = file_hash(client, "sip")
    bad = client.post("/exports", json={"file_hash": h, "filter": "sip.Method =="})
    assert bad.status_code == 400 and "Invalid display filter" in bad.json()["detail"]
    assert client.post("/exports", json={"file_hash": "0" * 64, "filter": "sip"}).status_code == 404
    assert client.post("/exports", json={"file_hash": "not-a-hash", "filter": "sip"}).status_code == 422


def test_validate_endpoint(client):
    assert client.get("/exports/validate", params={"filter": "sip || dns"}).json() == {"valid": True, "error": None}
    assert client.get("/exports/validate", params={"filter": "sip =="}).json()["valid"] is False
