import os
import re
import yaml
from enum import Enum
from pathlib import Path
from typing import Mapping, Optional, Set
from pydantic import BaseModel, Field, field_validator
from .logger import get_logger

logger = get_logger(__name__)


def parse_size_bytes(value, default: int) -> int:
    """'512M', '2G', '1024' or an int -> bytes. None or '' gives the default."""
    if value is None:
        return default
    if isinstance(value, int):
        if value < 0:
            raise ValueError(f"Size value must be non-negative: {value}")
        return value
    stripped = str(value).strip()
    if not stripped:
        return default
    match = re.fullmatch(r"(?i)(\d+(?:\.\d+)?)\s*([kmgt]?)b?", stripped)
    if not match:
        raise ValueError(f"Invalid size value: '{value}' (use bytes or a K/M/G/T suffix, e.g. 512M)")
    number_str, suffix = match.groups()
    multipliers = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}
    return int(float(number_str) * multipliers[suffix.lower()])


class RedisConfig(BaseModel):
    host: str = "redis"
    port: int = 6379
    # How long startup waits for Redis to be reachable and done loading its
    # dataset (a large catalog can take several seconds to load).
    wait_seconds: int = Field(120, ge=0)


class ScanMode(str, Enum):
    FULL = "full"
    QUICK = "quick"
    FAST = "fast"


class QuickScanConfig(BaseModel):
    pebc: float = 1.0
    min_file_size: int = 0
    config_version: str = "v1"

    @field_validator("min_file_size", mode="before")
    @classmethod
    def validate_min_file_size(cls, v):
        # Checked at startup, so a typo fails loudly instead of in the first scan.
        return parse_size_bytes(v, default=0)

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
    # Files at least this big (bytes, or "512M", "2G") are "large".
    large_file_size: int = 512 * 1024**2
    # How many large files may be scanned at the same time (each one costs about
    # 7 MB in fast mode and about 0.5 GB in full mode).
    large_file_parallel_scans: int = Field(1, ge=1)
    # tshark -M: drop dissector state every N packets so memory does not grow
    # with the number of flows in a capture. 0 disables it.
    tshark_session_reset: int = Field(500_000, ge=0)

    @field_validator("scan_mode", mode="before")
    @classmethod
    def lowercase_scan_mode(cls, v):
        return v.strip().lower() if isinstance(v, str) else v

    @field_validator("large_file_size", mode="before")
    @classmethod
    def validate_large_file_size(cls, v):
        return parse_size_bytes(v, default=512 * 1024**2)


class ExportConfig(BaseModel):
    # Filtered extracts are kept here and reused for the same file + filter.
    cache_dir: str = "/data/exports"
    # Oldest-used extracts are deleted once the cache grows past this.
    cache_max_size: int = 5 * 1024**3
    # Filter jobs running at once; each is a full tshark decode of the source.
    max_jobs: int = Field(2, ge=1)

    @field_validator("cache_max_size", mode="before")
    @classmethod
    def validate_cache_max_size(cls, v):
        return parse_size_bytes(v, default=5 * 1024**3)


class LogConfig(BaseModel):
    level: str = "INFO"


class AppConfig(BaseModel):
    port: int = 7000
    # Prefix for the download links the API returns. Empty = relative links
    # (/pcaps/download/...), which work behind the web UI's /api proxy.
    public_url: str = ""
    redis: RedisConfig = Field(default_factory=RedisConfig)
    pcap: PcapConfig = Field(default_factory=PcapConfig)
    export: ExportConfig = Field(default_factory=ExportConfig)
    log: LogConfig = Field(default_factory=LogConfig)


# backend/config/config.yaml, wherever the code runs (/app in the image).
CONFIG_PATH = str(Path(__file__).resolve().parents[1] / "config" / "config.yaml")

# Environment variable -> config key. Every setting can come from .env through
# docker-compose, the same way the other services are configured, so a
# deployment needs no config file at all: config.yaml is baked into the image
# and only supplies defaults. An environment variable always wins over it.
ENV_OVERRIDES = {
    "PORT": ("port",),
    "PUBLIC_URL": ("public_url",),
    "REDIS_HOST": ("redis", "host"),
    "REDIS_PORT": ("redis", "port"),
    "REDIS_WAIT_SECONDS": ("redis", "wait_seconds"),
    "PCAP_ROOT_DIRECTORY": ("pcap", "root_directory"),
    "PCAP_PREFIX_STR": ("pcap", "prefix_str"),
    "PCAP_SCAN_INTERVAL_SECONDS": ("pcap", "scan_interval_seconds"),
    "SCAN_MODE": ("pcap", "scan_mode"),
    "MAX_PARALLEL_SCANS": ("pcap", "max_parallel_scans"),
    "LARGE_FILE_SIZE": ("pcap", "large_file_size"),
    "LARGE_FILE_PARALLEL_SCANS": ("pcap", "large_file_parallel_scans"),
    "TSHARK_SESSION_RESET": ("pcap", "tshark_session_reset"),
    "QUICK_SCAN_PEBC": ("pcap", "quick_scan", "pebc"),
    "QUICK_SCAN_MIN_FILE_SIZE": ("pcap", "quick_scan", "min_file_size"),
    "QUICK_SCAN_CONFIG_VERSION": ("pcap", "quick_scan", "config_version"),
    "EXPORT_CACHE_MAX_SIZE": ("export", "cache_max_size"),
    "EXPORT_MAX_JOBS": ("export", "max_jobs"),
    "LOG_LEVEL": ("log", "level"),
}


def _read_yaml(config_path: str) -> dict:
    config_file = Path(config_path)
    if config_file.is_dir():
        # What Docker leaves behind when a compose file bind-mounts a config
        # file that does not exist on the host.
        print(f"[config] {config_path} is a directory, not a file; ignoring it and using defaults")
        return {}
    if not config_file.exists():
        print(f"[config] No config file at {config_path}; using defaults and environment variables")
        return {}
    with open(config_file, "r") as f:
        data = yaml.safe_load(f)
    print(f"[config] Loaded {config_path}")
    return data or {}


def load_config(config_path: str = CONFIG_PATH, environ: Optional[Mapping[str, str]] = None) -> AppConfig:
    """Defaults from config.yaml (if any), then environment variables on top."""
    data = _read_yaml(config_path)
    env = os.environ if environ is None else environ
    for var, keys in ENV_OVERRIDES.items():
        value = env.get(var)
        if value is None or value == "":
            continue
        node = data
        for key in keys[:-1]:
            if not isinstance(node.get(key), dict):
                node[key] = {}  # missing, or left empty in the YAML
            node = node[key]
        node[keys[-1]] = value
    return AppConfig(**data)


# Settings changed from the UI (the scan mode) are kept in Redis, next to the
# catalog they describe, instead of being written back into a config file.
SETTINGS_KEY = "pcap:settings"


def save_runtime_scan_mode(redis, mode: ScanMode) -> None:
    redis.hset(SETTINGS_KEY, "scan_mode", mode.value)


def apply_runtime_settings(redis, config: AppConfig) -> None:
    stored = redis.hget(SETTINGS_KEY, "scan_mode")
    if stored in {m.value for m in ScanMode}:
        configured = config.pcap.scan_mode
        config.pcap.scan_mode = ScanMode(stored)
        if ScanMode(stored) != configured:
            logger.info(
                "Scan mode %s (chosen in the UI) overrides the configured %s. "
                "Choose another mode in the UI, or run `redis-cli HDEL %s scan_mode`, to change it.",
                stored, ScanMode(configured).value, SETTINGS_KEY,
            )
        else:
            logger.info("Scan mode %s restored from the last change made in the UI", stored)