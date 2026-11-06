"""The catalog stays true to the disk: re-indexed, changed, deleted, vanishing
and growing files, cancelled scans, and the one-time index repair."""

import asyncio
import os
import threading

import pytest

import services.scan as scan_mod
from conftest import requires_tshark, run_scan, stored, dns_frame
from pcap_builder import sip_frame, write_pcap
from services.scan import (
    ScanState, ensure_index_version, get_scan_service, rebuild_protocol_index_sync,
)


def proto_set(ctx, proto):
    return ctx.redis_client.smembers(f"pcap:index:protocol:{proto}")


def catalog_hashes(ctx):
    return {k.rsplit(":", 1)[-1] for k in ctx.redis_client.scan_iter("pcap:file:*")}


def sha_of(ctx, path):
    return ctx.redis_client.hget("pcap:pathmap", str(path))


@requires_tshark
def test_rescan_removes_protocols_the_file_no_longer_has(ctx, sample_pcaps):
    # e.g. fast mode guessed "sip" from a port, the full decode does not find it
    run_scan(ctx)
    sha = sha_of(ctx, sample_pcaps["dns"])
    r = ctx.redis_client
    r.sadd("pcap:index:protocol:sip", sha)
    r.hset(f"pcap:file:{sha}", mapping={"protocols": "eth,ip,udp,dns,sip", "scan_mode": "fast"})

    assert run_scan(ctx)["indexed_files"] == 1          # fast -> full rescans it
    assert sha not in proto_set(ctx, "sip")
    assert "sip" not in stored(ctx, sample_pcaps["dns"])["protocols"]


@requires_tshark
def test_changed_file_replaces_its_old_entry(ctx, sample_pcaps):
    run_scan(ctx)
    old_sha = sha_of(ctx, sample_pcaps["sip"])
    write_pcap(sample_pcaps["sip"], [dns_frame(), dns_frame(), dns_frame(), dns_frame()])
    os.utime(sample_pcaps["sip"], (1, 1))

    run_scan(ctx)
    new_sha = sha_of(ctx, sample_pcaps["sip"])
    assert new_sha != old_sha
    assert old_sha not in catalog_hashes(ctx)            # no duplicate row for the old content
    assert old_sha not in proto_set(ctx, "sip")
    assert len(catalog_hashes(ctx)) == 3


@requires_tshark
def test_deleted_file_leaves_the_catalog(ctx, sample_pcaps):
    run_scan(ctx)
    sha = sha_of(ctx, sample_pcaps["dns"])
    sample_pcaps["dns"].unlink()

    result = run_scan(ctx)
    assert result["removed_files"] == 1
    assert sha not in catalog_hashes(ctx)
    assert sha not in proto_set(ctx, "dns")
    assert ctx.redis_client.hget("pcap:pathmap", str(sample_pcaps["dns"])) is None
    assert ctx.redis_client.zscore("pcap:sort:size_bytes", sha) is None
    # "dns" is still in mixed.pcap, so it stays in autocomplete
    assert ctx.redis_client.zscore("pcap:protocols:autocomplete", "dns") is not None


@requires_tshark
def test_protocol_nobody_has_any_more_leaves_autocomplete(ctx, sample_pcaps):
    run_scan(ctx)
    sample_pcaps["dns"].unlink()
    sample_pcaps["mixed"].unlink()
    run_scan(ctx)
    assert ctx.redis_client.zscore("pcap:protocols:autocomplete", "dns") is None
    assert ctx.redis_client.zscore("pcap:protocols:autocomplete", "sip") is not None


@requires_tshark
def test_empty_directory_does_not_wipe_the_catalog(ctx, sample_pcaps):
    # A missing or mistyped mount looks like "every file was deleted".
    run_scan(ctx)
    for f in sample_pcaps.values():
        f.unlink()
    assert run_scan(ctx)["removed_files"] == 0
    assert len(catalog_hashes(ctx)) == 3


@requires_tshark
def test_file_that_vanishes_after_listing_does_not_fail_the_scan(ctx, sample_pcaps, monkeypatch):
    ghost = str(sample_pcaps["sip"].parent / "ghost.pcap")
    real_walk = scan_mod.os.walk

    def walk_with_ghost(root):
        for dirpath, dirs, files in real_walk(root):
            yield dirpath, dirs, files + (["ghost.pcap"] if dirpath == str(sample_pcaps["sip"].parent) else [])

    monkeypatch.setattr(scan_mod.os, "walk", walk_with_ghost)
    result = run_scan(ctx)
    assert result["status"] == "success" and result["indexed_files"] == 3
    assert stored(ctx, ghost) == {}


@requires_tshark
def test_file_growing_during_its_scan_is_not_stored(ctx, sample_pcaps, monkeypatch):
    service = get_scan_service()
    real = service.get_protocols_from_pcap
    target = str(sample_pcaps["sip"])

    async def append_while_scanning(path, **kw):
        result = await real(path, **kw)
        if path == target:
            with open(path, "ab") as f:
                f.write(b"\0" * 64)          # a capture still being written
        return result

    monkeypatch.setattr(service, "get_protocols_from_pcap", append_while_scanning)
    assert run_scan(ctx)["indexed_files"] == 2
    assert stored(ctx, sample_pcaps["sip"]) == {}        # picked up again by the next scan


def test_cancel_does_not_stop_the_next_scan(ctx):
    service = get_scan_service()
    service.scan_cancel_event.set()                      # a cancel from an earlier scan
    assert service.try_begin_scan()
    assert not service.scan_cancel_event.is_set()


def test_only_one_scan_can_begin_at_a_time(ctx):
    service = get_scan_service()
    results = []
    barrier = threading.Barrier(8)

    def begin():
        barrier.wait()
        results.append(service.try_begin_scan())

    threads = [threading.Thread(target=begin) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1
    assert service.scan_status["state"] == ScanState.RUNNING


def test_a_failed_scan_does_not_block_the_next_one(ctx):
    service = get_scan_service()
    service.scan_status["state"] = ScanState.FAILED
    assert service.try_begin_scan()


@requires_tshark
def test_scan_status_reports_progress(ctx, sample_pcaps):
    service = get_scan_service()
    assert service.try_begin_scan()
    service.scan_wrapper()
    status = service.status_snapshot()
    assert status["state"] == "completed"
    assert status["total_files"] == 3 and status["processed_files"] == 3
    assert status["current_files"] == []


@requires_tshark
def test_index_repair_rebuilds_protocol_sets_from_the_entries(ctx, sample_pcaps):
    run_scan(ctx)
    r = ctx.redis_client
    dns_sha = sha_of(ctx, sample_pcaps["dns"])
    r.sadd("pcap:index:protocol:sip", dns_sha)           # stale membership from an old version
    r.sadd("pcap:index:protocol:ghostproto", dns_sha)
    r.zadd("pcap:protocols:autocomplete", {"ghostproto": 0})

    ensure_index_version(r)
    assert dns_sha not in proto_set(ctx, "sip")
    assert not r.exists("pcap:index:protocol:ghostproto")
    assert r.zscore("pcap:protocols:autocomplete", "ghostproto") is None
    assert r.hget("pcap:settings", "index_version") == scan_mod.INDEX_VERSION

    r.sadd("pcap:index:protocol:sip", dns_sha)
    ensure_index_version(r)                              # already current: not rebuilt again
    assert dns_sha in proto_set(ctx, "sip")
    assert rebuild_protocol_index_sync(r) == 3


@requires_tshark
def test_renamed_on_move_updates_the_name(ctx, sample_pcaps, pcap_dir):
    run_scan(ctx)
    sha = sha_of(ctx, sample_pcaps["dns"])
    moved = pcap_dir / "archive" / "renamed-dns.pcap"
    moved.parent.mkdir()
    sample_pcaps["dns"].rename(moved)
    run_scan(ctx)
    rec = ctx.redis_client.hgetall(f"pcap:file:{sha}")
    assert rec["filename"] == "renamed-dns.pcap"
    assert rec["filename_sort"] == "renamed-dns.pcap" and rec["path_sort"] == str(moved).lower()


@requires_tshark
def test_upper_case_extension_is_scanned(ctx, pcap_dir):
    write_pcap(pcap_dir / "CALL.PCAP", [sip_frame()])
    assert run_scan(ctx)["indexed_files"] == 1
