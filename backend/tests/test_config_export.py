"""Configuration (services/config.py) and export helpers (services/export.py)."""

import os
import time
from pathlib import Path

import fakeredis
import pytest
from pydantic import ValidationError

from conftest import requires_tshark
from services.config import (
    AppConfig, PcapConfig, ScanMode, apply_runtime_settings, load_config, save_runtime_scan_mode,
)
from services.export import ExportService, download_name, export_id, normalize_filter

IMAGE_CONFIG = Path(__file__).resolve().parents[1] / "config" / "config.yaml"


# --- load_config: image defaults, then environment variables ---

def test_image_config_alone_gives_working_defaults():
    config = load_config(str(IMAGE_CONFIG), environ={})
    assert config.port == 7000 and config.public_url == ""
    assert config.pcap.root_directory == "/pcaps" and config.pcap.scan_mode == ScanMode.FAST


def test_environment_overrides_the_file():
    config = load_config(str(IMAGE_CONFIG), environ={
        "PORT": "7100", "SCAN_MODE": "full", "REDIS_HOST": "cache.internal", "REDIS_PORT": "6390",
        "LOG_LEVEL": "DEBUG", "MAX_PARALLEL_SCANS": "8", "QUICK_SCAN_PEBC": "0.25",
        "EXPORT_MAX_JOBS": "3", "PCAP_PREFIX_STR": "/srv/pcaps",
    })
    assert config.port == 7100
    assert config.pcap.scan_mode == ScanMode.FULL
    assert (config.redis.host, config.redis.port) == ("cache.internal", 6390)
    assert config.log.level == "DEBUG"
    assert config.pcap.max_parallel_scans == 8
    assert config.pcap.quick_scan.pebc == 0.25
    assert config.export.max_jobs == 3
    assert config.pcap.prefix_str == "/srv/pcaps"


def test_empty_environment_value_keeps_the_default():
    # docker-compose passes unset .env values through as empty strings
    assert load_config(str(IMAGE_CONFIG), environ={"SCAN_MODE": "", "PORT": ""}).port == 7000


def test_config_path_that_docker_turned_into_a_directory(tmp_path):
    # Bind-mounting a config file that does not exist makes Docker create an
    # empty directory with that name; startup must not fail because of it.
    fake = tmp_path / "config.yml"
    fake.mkdir()
    config = load_config(str(fake), environ={"SCAN_MODE": "quick"})
    assert config.pcap.scan_mode == ScanMode.QUICK and config.port == 7000


def test_missing_config_file_uses_defaults(tmp_path):
    assert load_config(str(tmp_path / "nope.yaml"), environ={}) == AppConfig()


def test_env_value_fills_a_section_left_empty_in_yaml(tmp_path):
    f = tmp_path / "config.yaml"
    f.write_text("pcap:\n  quick_scan:\n")
    assert load_config(str(f), environ={"QUICK_SCAN_PEBC": "0.5"}).pcap.quick_scan.pebc == 0.5


def test_invalid_environment_value_is_rejected():
    with pytest.raises(ValidationError):
        load_config(str(IMAGE_CONFIG), environ={"SCAN_MODE": "turbo"})


# --- scan mode chosen in the UI, stored with the catalog ---

def test_ui_scan_mode_is_restored_from_redis():
    r = fakeredis.FakeRedis(decode_responses=True)
    config = AppConfig()
    apply_runtime_settings(r, config)               # nothing stored: unchanged
    assert config.pcap.scan_mode == ScanMode.FULL
    save_runtime_scan_mode(r, ScanMode.QUICK)
    apply_runtime_settings(r, config)
    assert config.pcap.scan_mode == ScanMode.QUICK


def test_unknown_stored_scan_mode_is_ignored():
    r = fakeredis.FakeRedis(decode_responses=True)
    r.hset("pcap:settings", "scan_mode", "turbo")
    config = AppConfig()
    apply_runtime_settings(r, config)
    assert config.pcap.scan_mode == ScanMode.FULL


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


def test_bad_size_is_rejected_at_startup():
    with pytest.raises(ValidationError):
        load_config(str(IMAGE_CONFIG), environ={"LARGE_FILE_SIZE": "lots"})
    config = load_config(str(IMAGE_CONFIG), environ={"LARGE_FILE_SIZE": "2G", "EXPORT_CACHE_MAX_SIZE": "10G"})
    assert config.pcap.large_file_size == 2 * 1024**3 and config.export.cache_max_size == 10 * 1024**3


def test_scan_mode_is_not_case_sensitive():
    assert load_config(str(IMAGE_CONFIG), environ={"SCAN_MODE": "FULL"}).pcap.scan_mode == ScanMode.FULL


def test_large_file_parallel_scans_setting():
    assert load_config(str(IMAGE_CONFIG), environ={}).pcap.large_file_parallel_scans == 1
    assert load_config(str(IMAGE_CONFIG), environ={"LARGE_FILE_PARALLEL_SCANS": "3"}).pcap.large_file_parallel_scans == 3


def test_normalize_filter_keeps_quoted_whitespace():
    assert normalize_filter('frame contains "a  b"   &&  udp') == 'frame contains "a  b" && udp'
    assert normalize_filter(r'sip.from == "x\"  y"  ||  dns') == r'sip.from == "x\"  y" || dns'


def test_new_extract_bigger_than_the_cache_is_kept(tmp_path):
    svc = ExportService(cache_dir=str(tmp_path), cache_max_size=100, max_jobs=1, session_reset=0)
    big = tmp_path / "big.pcapng"
    big.write_bytes(b"x" * 500)
    svc._evict(keep=big)
    assert big.exists()   # used to evict itself: "ready", then 404 on download
