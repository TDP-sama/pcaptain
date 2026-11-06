"""Waiting for Redis at startup (services/context.py).

A large catalog takes Redis several seconds to load; meanwhile every command
fails with "Redis is loading the dataset in memory". The old startup gave up on
the first error and the service stayed broken until restarted.
"""

import redis

from services.config import AppConfig
from services.context import AppContext


class FlakyRedis:
    """Answers PING with the given errors first, then succeeds."""

    def __init__(self, *errors):
        self.errors = list(errors)
        self.pings = 0

    def ping(self):
        self.pings += 1
        if self.errors:
            raise self.errors.pop(0)
        return True


def context_with(client):
    ctx = AppContext(AppConfig())
    ctx.redis_client = client
    return ctx


def test_client_exists_even_when_redis_is_down():
    ctx = AppContext(AppConfig())
    ctx.initialize()                       # nothing listens on redis:6379 here
    assert ctx.redis_client is not None    # used to be None, which broke every request for good


def test_redis_state():
    loading = redis.exceptions.BusyLoadingError("Redis is loading the dataset in memory")
    down = redis.exceptions.ConnectionError("Connection refused")
    assert context_with(FlakyRedis()).redis_state() == "ready"
    assert context_with(FlakyRedis(loading)).redis_state() == "loading"
    assert context_with(FlakyRedis(down)).redis_state() == "down"


def test_waits_while_redis_loads_then_succeeds():
    loading = redis.exceptions.BusyLoadingError("Redis is loading the dataset in memory")
    client = FlakyRedis(loading, loading, redis.exceptions.ConnectionError("refused"), loading)
    assert context_with(client).wait_for_redis(timeout=5, interval=0.01) is True
    assert client.pings == 5


def test_gives_up_after_the_timeout():
    client = FlakyRedis(*[redis.exceptions.ConnectionError("refused")] * 1000)
    assert context_with(client).wait_for_redis(timeout=0.05, interval=0.01) is False
