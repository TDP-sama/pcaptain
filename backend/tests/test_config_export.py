"""Config persistence (services/config.py) and export helpers (services/export.py)."""

import os
import time

import pytest
from pydantic import ValidationError

from conftest import requires_tshark
from services.config import PcapConfig, ScanMode, save_scan_mode
from services.export import ExportService, download_name, export_id, normalize_filter

CONFIG_TEXT = """pcap:
  root_directory: /pcaps
  scan_interval_seconds: 3600 # 1 hour
  scan_mode: fast # options: full, quick, fast
log:
  level: INFO
"""


def test_save_scan_mode_changes_only_that_value(tmp_path):
    f = tmp_path / "config.yaml"
    f.write_text(CONFIG_TEXT)
    assert save_scan_mode(ScanMode.FULL, str(f)) is True
    assert f.read_text() == CONFIG_TEXT.replace("scan_mode: fast #", "scan_mode: full #")


def test_save_scan_mode_without_the_line(tmp_path):
    f = tmp_path / "config.yaml"
    f.write_text("log:\n  level: INFO\n")
    assert save_scan_mode(ScanMode.FULL, str(f)) is False
    assert save_scan_mode(ScanMode.FULL, str(tmp_path / "missing.yaml")) is False


def test_pcap_config_validates_limits():
    with pytest.raises(ValidationError):
        PcapConfig(max_parallel_scans=0)
    with pytest.raises(ValidationError):
        PcapConfig(tshark_session_reset=-1)


# --- export helpers ---

def test_normalize_filter_collapses_whitespace():
    assert normalize_filter("  sip  ||\n sdp ") == "sip || sdp"


def test_export_id_is_stable_and_specific():
    a = export_id("f" * 64, "sip")
    assert a == export_id("f" * 64, "sip")
    assert a != export_id("f" * 64, "sdp")
    assert a != export_id("e" * 64, "sip")
    assert len(a) == 32


def test_download_name():
    assert download_name("call.pcap", 'sip.Method == "INVITE"') == "call__sip-Method-INVITE.pcapng"
    assert download_name("trace.pcapng.gz", "!!!") == "trace__filtered.pcapng"


def test_cache_evicts_least_recently_used(tmp_path):
    svc = ExportService(cache_dir=str(tmp_path), cache_max_size=100, max_jobs=1, session_reset=0)
    old, new = tmp_path / "old.pcapng", tmp_path / "new.pcapng"
    old.write_bytes(b"x" * 60)
    new.write_bytes(b"x" * 60)
    past = time.time() - 3600
    os.utime(old, (past, past))
    svc._evict()  # 120 bytes > 100: the older one goes
    assert not old.exists() and new.exists()
    assert (tmp_path / ".empty.pcap").exists()  # the validator's helper file is not an extract


def test_leftover_partial_files_are_removed_on_start(tmp_path):
    (tmp_path / "abc.part").write_bytes(b"half")
    ExportService(cache_dir=str(tmp_path), cache_max_size="1G", max_jobs=1, session_reset=0)
    assert not (tmp_path / "abc.part").exists()


@requires_tshark
def test_validate_display_filter(tmp_path):
    svc = ExportService(cache_dir=str(tmp_path), cache_max_size="1G", max_jobs=1, session_reset=0)
    assert svc.validate('sip.Method == "INVITE" || sdp') is None
    assert svc.validate("sip.Method ==")  # tshark's error message
    assert svc.validate("") == "The filter is empty."
