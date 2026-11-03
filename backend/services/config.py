import re
import yaml
from enum import Enum
from pathlib import Path
from typing import Optional, Set
from pydantic import BaseModel, Field, field_validator
from .logger import get_logger

logger = get_logger(__name__)


class RedisConfig(BaseModel):
    host: str = "redis"
    port: int = 6379


class ScanMode(str, Enum):
    FULL = "full"
    QUICK = "quick"
    FAST = "fast"


class QuickScanConfig(BaseModel):
    pebc: float = 1.0
    min_file_size: int | str = 0
    config_version: str = "v1"

    @field_validator("pebc")
    @classmethod
    def validate_pebc(cls, v: float) -> float:
        if v <= 0 or v > 1:
            raise ValueError("quick_scan.pebc must be > 0 and <= 1")
        return v

class PcapConfig(BaseModel):
    root_directory: str = "/pcaps"
    prefix_str: Optional[str] = None
    allowed_file_extensions: Set[str] = Field(default_factory=lambda: {".pcap", ".pcapng", ".cap"})
    scan_interval_seconds: int = 300
    scan_mode: ScanMode = ScanMode.FULL
    quick_scan: QuickScanConfig = Field(default_factory=QuickScanConfig)
    # How many files are scanned at the same time.
    max_parallel_scans: int = Field(4, ge=1)
    # Files at least this big (bytes, or "512M", "2G") are scanned one at a time.
    large_file_size: int | str = "512M"
    # tshark -M: drop dissector state every N packets so memory does not grow
    # with the number of flows in a capture. 0 disables it.
    tshark_session_reset: int = Field(500_000, ge=0)


class ExportConfig(BaseModel):
    # Filtered extracts are kept here and reused for the same file + filter.
    cache_dir: str = "/data/exports"
    # Oldest-used extracts are deleted once the cache grows past this.
    cache_max_size: int | str = "5G"
    # Filter jobs running at once; each is a full tshark decode of the source.
    max_jobs: int = Field(2, ge=1)


class LogConfig(BaseModel):
    level: str = "INFO"


class AppConfig(BaseModel):
    port: int = 8080
    public_url: str = "http://localhost:8080"
    redis: RedisConfig = Field(default_factory=RedisConfig)
    pcap: PcapConfig = Field(default_factory=PcapConfig)
    export: ExportConfig = Field(default_factory=ExportConfig)
    log: LogConfig = Field(default_factory=LogConfig)


CONFIG_PATH = "/app/config/config.yaml"


def save_scan_mode(mode: ScanMode, config_path: str = CONFIG_PATH) -> bool:
    """Persist pcap.scan_mode in the YAML file so it survives a restart.

    Rewrites only the value on the `scan_mode:` line, keeping the file's
    comments and layout. Returns False if the file or the line is missing.
    """
    config_file = Path(config_path)
    if not config_file.exists():
        return False
    text = config_file.read_text()
    new_text, n = re.subn(
        r"^(\s*scan_mode:\s*)[A-Za-z]+",
        lambda m: m.group(1) + mode.value,
        text,
        count=1,
        flags=re.MULTILINE,
    )
    if n == 0:
        return False
    config_file.write_text(new_text)
    return True


def load_config(config_path: str = CONFIG_PATH) -> AppConfig:
    """
    Load configuration from YAML file and parse into AppConfig model.
    """
    config_file = Path(config_path)

    if not config_file.exists():
        print(f"[config] Config file not found at {config_path}, using defaults")
        return AppConfig()

    try:
        with open(config_file, "r") as f:
            yaml_data = yaml.safe_load(f)

        if yaml_data is None:
            print(f"[config] Empty config file at {config_path}, using defaults")
            return AppConfig()

        print(f"[config] Successfully loaded configuration from {config_path}")
        return AppConfig(**yaml_data)

    except yaml.YAMLError as e:
        print(f"[config] Error parsing YAML config: {e}")
        raise
    except Exception as e:
        print(f"[config] Error loading config: {e}")
        raise