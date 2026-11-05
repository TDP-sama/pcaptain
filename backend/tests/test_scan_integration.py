"""End to end scans with the real tshark / fastscan on tiny generated captures."""

import os

import pytest

import services.scan as scan_mod
from conftest import requires_fastscan, requires_tshark, run_scan, sll_sip_pcap, stored, dns_frame
from pcap_builder import write_pcap


@requires_tshark
def test_full_scan_indexes_every_capture(ctx, sample_pcaps):
    assert run_scan(ctx) == {"status": "success", "indexed_files": 3}
    sip = stored(ctx, sample_pcaps["sip"])
    assert set(sip["protocols"].split(",")) >= {"eth", "ip", "udp", "sip"}
    assert sip["total_packets"] == "3"      # counted during the scan, no capinfos pass
    assert sip["scan_mode"] == "full"
    assert "dns" not in sip["protocols"]
    r = ctx.redis_client
    assert r.smembers("pcap:index:protocol:sip") == {
        r.hget("pcap:pathmap", str(sample_pcaps["sip"])),
        r.hget("pcap:pathmap", str(sample_pcaps["mixed"])),
    }


@requires_tshark
def test_rescan_of_unchanged_files_reads_nothing(ctx, sample_pcaps, monkeypatch):
    run_scan(ctx)
    hashed = []
    real_hash = scan_mod.calculate_sha256_sync
    monkeypatch.setattr(scan_mod, "calculate_sha256_sync", lambda p: hashed.append(p) or real_hash(p))
    assert run_scan(ctx)["indexed_files"] == 0
    assert hashed == []                     # skipped on path + size + mtime, never hashed


@requires_tshark
def test_changed_file_is_rescanned(ctx, sample_pcaps):
    run_scan(ctx)
    write_pcap(sample_pcaps["sip"], [dns_frame()])      # same path, new content
    os.utime(sample_pcaps["sip"], (1, 1))
    assert run_scan(ctx)["indexed_files"] == 1
    assert "dns" in stored(ctx, sample_pcaps["sip"])["protocols"]


@requires_tshark
def test_duplicate_content_is_stored_once(ctx, sample_pcaps, pcap_dir):
    (pcap_dir / "copy-of-sip.pcap").write_bytes(sample_pcaps["sip"].read_bytes())
    assert run_scan(ctx)["indexed_files"] == 3          # 4 files, one is a duplicate


@requires_tshark
def test_unreadable_file_does_not_stop_the_scan(ctx, sample_pcaps, pcap_dir):
    (pcap_dir / "broken.pcap").write_bytes(b"this is not a capture")
    assert run_scan(ctx)["indexed_files"] == 3
    assert stored(ctx, pcap_dir / "broken.pcap") == {}


@requires_tshark
def test_moved_file_keeps_its_record(ctx, sample_pcaps, pcap_dir):
    run_scan(ctx)
    sha = ctx.redis_client.hget("pcap:pathmap", str(sample_pcaps["dns"]))
    moved = pcap_dir / "archive" / "dns.pcap"
    moved.parent.mkdir()
    sample_pcaps["dns"].rename(moved)
    assert run_scan(ctx)["indexed_files"] == 0
    assert ctx.redis_client.hget(f"pcap:file:{sha}", "path") == str(moved)
    assert ctx.redis_client.hget("pcap:pathmap", str(moved)) == sha


@requires_fastscan
@requires_tshark
def test_fast_mode_falls_back_to_tshark_for_unknown_link_types(ctx, pcap_dir):
    ctx.config.pcap.scan_mode = "fast"
    f = sll_sip_pcap(pcap_dir / "cooked.pcap")
    assert run_scan(ctx)["indexed_files"] == 1
    rec = stored(ctx, f)
    assert rec["scan_mode"] == "full"                  # fastscan saw nothing, tshark decoded it
    assert {"sll", "sip"} <= set(rec["protocols"].split(","))


@requires_fastscan
def test_fast_mode_counts_every_packet(ctx, sample_pcaps):
    ctx.config.pcap.scan_mode = "fast"
    run_scan(ctx)
    rec = stored(ctx, sample_pcaps["mixed"])
    assert rec["scan_mode"] == "fast"
    assert rec["total_packets"] == "2"


@requires_fastscan
@requires_tshark
def test_switching_fast_to_full_rescans(ctx, sample_pcaps):
    ctx.config.pcap.scan_mode = "fast"
    run_scan(ctx)
    ctx.config.pcap.scan_mode = "full"
    assert run_scan(ctx)["indexed_files"] == 3
    assert stored(ctx, sample_pcaps["sip"])["scan_mode"] == "full"
