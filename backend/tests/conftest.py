"""Shared fixtures.

Every test gets its own AppContext with a fake Redis and temporary directories,
so nothing touches the real catalog, config.yaml or ~/pcaps. Run from backend/:
    python -m pytest
"""

import asyncio
import shutil
import sys
from pathlib import Path

import fakeredis
import pytest

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

import services.context as context_mod  # noqa: E402
import services.export as export_mod  # noqa: E402
from services.config import AppConfig, ExportConfig, PcapConfig  # noqa: E402
from services.context import AppContext  # noqa: E402
from services.scan import ScanService, ScanState, get_scan_service  # noqa: E402

from pcap_builder import dns_frame, linux_sll, ipv4_udp, sip_frame, write_pcap, LINKTYPE_LINUX_SLL, SIP_OPTIONS  # noqa: E402

requires_tshark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
requires_fastscan = pytest.mark.skipif(shutil.which("fastscan") is None, reason="fastscan not built")


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    """An app context wired to a fake Redis, an empty pcap dir and a temp export cache."""
    pcaps = tmp_path / "pcaps"
    pcaps.mkdir()
    config = AppConfig(
        public_url="http://testserver",
        pcap=PcapConfig(root_directory=str(pcaps), prefix_str=None, scan_mode="full", max_parallel_scans=2),
        export=ExportConfig(cache_dir=str(tmp_path / "exports"), max_jobs=1),
    )
    context = AppContext(config)
    context.redis_client = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(context_mod, "_app_context", context)
    monkeypatch.setattr(export_mod, "_service", None)
    yield context
    # ScanService keeps these on the class; never leak them into the next test
    ScanService.scan_cancel_event.clear()
    ScanService.scan_status.update(
        state=ScanState.IDLE, indexed_files=0, total_files=0, processed_files=0,
        current_files=[], removed_files=0,
    )


@pytest.fixture
def pcap_dir(ctx):
    return Path(ctx.config.pcap.root_directory)


@pytest.fixture
def sample_pcaps(pcap_dir):
    """Four captures: SIP only, DNS only, SIP + DNS, and SIP over Linux cooked capture."""
    return {
        "sip": write_pcap(pcap_dir / "sip.pcap", [sip_frame(), sip_frame(), sip_frame()]),
        "dns": write_pcap(pcap_dir / "dns.pcap", [dns_frame(), dns_frame()]),
        "mixed": write_pcap(pcap_dir / "mixed.pcap", [sip_frame(), dns_frame()]),
    }


def run_scan(ctx) -> dict:
    """Run one full scan of ctx's pcap dir and return its summary."""
    return asyncio.run(get_scan_service().scan_and_index())


def sll_sip_pcap(path: Path) -> Path:
    return write_pcap(path, [linux_sll(ipv4_udp(5060, 5060, SIP_OPTIONS))], linktype=LINKTYPE_LINUX_SLL)


def stored(ctx, path: Path) -> dict:
    """The catalog record for a file, looked up through the path map."""
    r = ctx.redis_client
    sha = r.hget("pcap:pathmap", str(path))
    return r.hgetall(f"pcap:file:{sha}") if sha else {}


__all__ = ["requires_tshark", "requires_fastscan", "run_scan", "sll_sip_pcap", "stored", "dns_frame"]
