"""Pure scan logic in services/scan.py: no tshark, no real Redis."""

import asyncio
import hashlib
import os
import sys

import fakeredis
import pytest

from services.config import ScanMode
from services.scan import (
    HASH_CHUNK_BYTES,
    ScanService,
    calculate_sha256_sync,
    get_effective_scan_mode,
    parse_size_bytes,
    should_rescan_file,
)


# --- should_rescan_file: when a change of scan settings forces a rescan ---

def rescan(stored, current, stored_pebc=None, current_pebc=None, stored_version="v1", current_version="v1"):
    return should_rescan_file(
        current_scan_mode=current, current_pebc=current_pebc, current_config_version=current_version,
        stored_scan_mode=stored, stored_pebc=stored_pebc, stored_config_version=stored_version,
    )


def test_fast_to_full_rescans():
    # The original compared against "normal", so this never happened.
    assert rescan("fast", "full") is True


def test_quick_to_full_or_fast_rescans():
    assert rescan("quick", "full") is True
    assert rescan("quick", "fast") is True


def test_full_result_is_kept_when_switching_down():
    assert rescan("full", "fast") is False
    assert rescan("full", "quick") is False


def test_same_mode_is_not_rescanned():
    assert rescan("fast", "fast") is False
    assert rescan("full", "full") is False


def test_never_scanned_is_rescanned():
    assert rescan(None, "fast") is True


def test_quick_rescans_on_larger_share_or_new_version():
    assert rescan("quick", "quick", stored_pebc=0.1, current_pebc=0.2) is True
    assert rescan("quick", "quick", stored_pebc=0.2, current_pebc=0.1) is False
    assert rescan("quick", "quick", stored_pebc=0.1, current_pebc=0.1, current_version="v2") is True


# --- small helpers ---

@pytest.mark.parametrize("text, expected", [
    ("512M", 512 * 1024**2), ("2G", 2 * 1024**3), ("1.5k", 1536), ("1024", 1024), (" 3 m ", 3 * 1024**2),
])
def test_parse_size_bytes(text, expected):
    assert parse_size_bytes(text, default=0) == expected


def test_parse_size_bytes_rejects_garbage():
    with pytest.raises(ValueError):
        parse_size_bytes("lots", default=0)


def test_effective_scan_mode():
    kw = dict(quick_scan_pebc=0.1, quick_scan_min_file_size_bytes=1000, quick_scan_config_version="v1")
    assert get_effective_scan_mode(10, ScanMode.FAST, **kw)[0] == ScanMode.FAST
    assert get_effective_scan_mode(10, ScanMode.QUICK, **kw)[0] == ScanMode.FULL       # too small to sample
    assert get_effective_scan_mode(5000, ScanMode.QUICK, **kw)[:2] == (ScanMode.QUICK, 0.1)


def test_sha256_matches_hashlib_across_chunks(tmp_path):
    data = os.urandom(3 * HASH_CHUNK_BYTES + 123)  # spans several 1 MiB reads
    f = tmp_path / "blob.bin"
    f.write_bytes(data)
    assert calculate_sha256_sync(str(f)) == hashlib.sha256(data).hexdigest()


# --- _stream_protocol_counts: counting while reading ---

def fake_tool(lines, exit_code=0, stderr=""):
    """A command that prints the given lines like tshark/fastscan would."""
    script = (
        "import sys\n"
        f"for line in {lines!r}: print(line)\n"
        f"sys.stderr.write({stderr!r})\n"
        f"sys.exit({exit_code})\n"
    )
    return [sys.executable, "-c", script]


def count(lines, **kw):
    return ScanService()._stream_protocol_counts(fake_tool(lines, **kw), "fake", "test.pcap")


def test_counts_packets_per_protocol():
    protocols, packets = count(["eth:ip:udp:sip", "eth:ip:udp:sip", "eth:ip:udp:dns"])
    assert packets == 3
    assert protocols == {"eth": 3, "ip": 3, "udp": 3, "sip": 2, "dns": 1}


def test_protocol_twice_in_one_packet_counts_once():
    protocols, packets = count(["eth:ip:gre:ip:udp"])
    assert protocols["ip"] == 1


def test_empty_line_is_a_packet_without_protocols():
    # fastscan prints an empty line for a packet it cannot decode
    protocols, packets = count(["eth:ip:udp", ""])
    assert packets == 2
    assert protocols == {"eth": 1, "ip": 1, "udp": 1}


def test_truncated_capture_keeps_what_was_read():
    # tshark exits non-zero on a file cut mid-packet, after printing the good packets
    result = count(["eth:ip:udp"], exit_code=2, stderr="appears to have been cut short")
    assert result == ({"eth": 1, "ip": 1, "udp": 1}, 1)


def test_failure_without_output_is_an_error():
    assert count([], exit_code=2, stderr="isn't a capture file") is None


def test_missing_tool_is_an_error():
    assert ScanService()._stream_protocol_counts(["no-such-tool-xyz"], "fake", "x") is None


def test_cancel_stops_reading():
    ScanService.scan_cancel_event.set()
    try:
        assert count(["eth:ip"] * 50) is None
    finally:
        ScanService.scan_cancel_event.clear()


def test_many_packets_keep_only_distinct_stacks():
    # 200k packets but two distinct lines: the result must still be exact.
    # The tool generates the lines itself (200k lines would not fit in argv).
    script = "for _ in range(100_000):\n    print('eth:ip:udp:sip'); print('eth:ip:udp:rtp')"
    protocols, packets = ScanService()._stream_protocol_counts(
        [sys.executable, "-c", script], "fake", "test.pcap")
    assert packets == 200_000
    assert protocols["udp"] == 200_000 and protocols["sip"] == 100_000


# --- is_unchanged_since_index: skip unchanged files without hashing ---

@pytest.fixture
def indexed(tmp_path):
    """A fake Redis holding one indexed file, plus that file on disk."""
    f = tmp_path / "a.pcap"
    f.write_bytes(b"x" * 100)
    st = f.stat()
    r = fakeredis.FakeRedis(decode_responses=True)
    r.hset("pcap:pathmap", str(f), "abc")
    r.hset("pcap:file:abc", mapping={
        "path": str(f), "size_bytes": st.st_size, "last_modified": st.st_mtime,
        "scan_mode": "fast", "config_version": "v1",
    })
    return r, f, st


def unchanged(r, path, size, mtime, mode=ScanMode.FAST):
    return asyncio.run(ScanService().is_unchanged_since_index(
        redis_client=r, file_path=str(path), file_size=size, mtime=mtime,
        current_scan_mode=mode, current_pebc=None, current_config_version="v1",
    ))


def test_unchanged_file_is_skipped(indexed):
    r, f, st = indexed
    assert unchanged(r, f, st.st_size, st.st_mtime) is True
    assert r.hget("pcap:file:abc", "last_scanned") is not None


def test_changed_size_or_mtime_is_scanned(indexed):
    r, f, st = indexed
    assert unchanged(r, f, st.st_size + 1, st.st_mtime) is False
    assert unchanged(r, f, st.st_size, st.st_mtime + 5) is False


def test_mode_upgrade_is_scanned(indexed):
    r, f, st = indexed
    assert unchanged(r, f, st.st_size, st.st_mtime, mode=ScanMode.FULL) is False


def test_unknown_path_is_scanned(indexed, tmp_path):
    r, _, st = indexed
    assert unchanged(r, tmp_path / "other.pcap", st.st_size, st.st_mtime) is False
