import asyncio
import time
from redis import Redis
from redis.exceptions import BusyLoadingError, ConnectionError, TimeoutError as RedisTimeoutError
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from .logger import get_logger
from .config import AppConfig, load_config

logger = get_logger(__name__)

class AppContext:

    def __init__(self, config: AppConfig = None):
        self.config = config or load_config()
        self.redis_client: Optional[Redis] = None
        self.thread_executor = ThreadPoolExecutor()

    
    def initialize(self):
        self.__initialize_redis__()
    
    async def initialize_async(self):
        pass
    
    ## Redis Initialization ##
    def __initialize_redis__(self):
        # Always create the client: redis-py connects lazily and reconnects on
        # its own. The old code set it to None when the first ping failed
        # (e.g. "Redis is loading the dataset in memory"), and the service then
        # stayed broken until it was restarted. wait_for_redis() does the wait.
        # Timeouts: a Redis that accepts connections but never answers (hung,
        # or a firewall dropping packets) must turn into a 503, not requests
        # that hang forever.
        self.redis_client = Redis(
            host=self.config.redis.host,
            port=self.config.redis.port,
            db=0,
            decode_responses=True,
            socket_connect_timeout=3,
            socket_timeout=30,
            health_check_interval=30,
        )

    def redis_state(self) -> str:
        """'ready', 'loading' (Redis is reading its dump file) or 'down'."""
        try:
            self.redis_client.ping()
            return "ready"
        except BusyLoadingError:
            return "loading"
        except (ConnectionError, RedisTimeoutError, OSError):
            return "down"

    def wait_for_redis(self, timeout: float, interval: float = 1.0) -> bool:
        """Block until Redis answers PING (and has finished loading), up to timeout seconds."""
        target = f"{self.config.redis.host}:{self.config.redis.port}"
        deadline = time.monotonic() + timeout
        last_state = None
        while True:
            state = self.redis_state()
            if state == "ready":
                logger.info("Connected to Redis at %s", target)
                return True
            if state != last_state:
                logger.warning(
                    "Redis at %s is %s; waiting up to %ss",
                    target, "loading its dataset" if state == "loading" else "not reachable", int(timeout),
                )
                last_state = state
            if time.monotonic() >= deadline:
                logger.error("Redis at %s still %s after %ss", target, state, int(timeout))
                return False
            time.sleep(interval)
    
_app_context: Optional[AppContext] = None

def init_app_context(config: AppConfig) -> AppContext:
    global _app_context
    if _app_context is not None:
        return _app_context

    _app_context = AppContext(config)
    _app_context.initialize()
    return _app_context

def get_app_context() -> AppContext:
    if _app_context is None:
        raise RuntimeError("AppContext not initialized")
    return _app_context

from functools import wraps
from inspect import signature
from typing import Callable, TypeVar
from typing_extensions import ParamSpec

P = ParamSpec("P")
R = TypeVar("R")

def with_app_context(func: Callable[P, R]) -> Callable[P, R]:
    sig = signature(func)
    if "context" not in sig.parameters:
        raise ValueError(
            "The decorated function must have a 'context' parameter."
        )

    @wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        if kwargs.get("context") is None:
            kwargs["context"] = get_app_context()
        return func(*args, **kwargs)
    return wrapper