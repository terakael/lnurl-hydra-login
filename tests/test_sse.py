from __future__ import annotations

import asyncio
import json

import pytest

from lnurl_hydra_login.sse import RedisSseManager


class FakePubSub:
    def __init__(self, messages: list[dict] | None = None, *, hang: bool = False):
        self.messages = messages or []
        self.hang = hang
        self.subscribed_channels: list[str] = []
        self.closed = False

    async def subscribe(self, channel: str) -> None:
        self.subscribed_channels.append(channel)

    async def listen(self):
        if self.hang:
            while True:
                await asyncio.sleep(1)
        for message in self.messages:
            yield message

    async def aclose(self) -> None:
        self.closed = True


class FakeRedis:
    def __init__(self, *, cached: str | None = None, pubsub: FakePubSub | None = None):
        self.cached = cached
        self.pubsub_instance = pubsub or FakePubSub()
        self.setex_calls: list[tuple[str, int, str]] = []
        self.publish_calls: list[tuple[str, str]] = []
        self.get_calls: list[str] = []
        self.operations: list[tuple[str, str]] = []

    async def setex(self, key: str, ttl: int, payload: str) -> None:
        self.operations.append(("setex", key))
        self.setex_calls.append((key, ttl, payload))

    async def publish(self, channel: str, payload: str) -> None:
        self.operations.append(("publish", channel))
        self.publish_calls.append((channel, payload))

    async def get(self, key: str) -> str | None:
        self.get_calls.append(key)
        return self.cached

    def pubsub(self) -> FakePubSub:
        return self.pubsub_instance


@pytest.mark.asyncio
async def test_publish_auth_caches_and_publishes(monkeypatch):
    fake_redis = FakeRedis()
    monkeypatch.setattr("lnurl_hydra_login.sse.aioredis.from_url", lambda *_args, **_kwargs: fake_redis)

    manager = RedisSseManager("redis://fake")
    await manager.publish_auth("k1-123", "https://hydra.example.com/done")

    payload = json.dumps({"redirect_to": "https://hydra.example.com/done"})
    assert fake_redis.setex_calls == [("lnurl:result:k1-123", 60, payload)]
    assert fake_redis.publish_calls == [("lnurl:auth:k1-123", payload)]
    assert fake_redis.operations == [
        ("setex", "lnurl:result:k1-123"),
        ("publish", "lnurl:auth:k1-123"),
    ]


@pytest.mark.asyncio
async def test_listen_for_auth_returns_cached_result(monkeypatch):
    fake_redis = FakeRedis(cached=json.dumps({"redirect_to": "https://hydra.example.com/cached"}))
    monkeypatch.setattr("lnurl_hydra_login.sse.aioredis.from_url", lambda *_args, **_kwargs: fake_redis)

    manager = RedisSseManager("redis://fake")
    results = [redirect async for redirect in manager.listen_for_auth("k1-123")]

    assert results == ["https://hydra.example.com/cached"]
    assert fake_redis.get_calls == ["lnurl:result:k1-123"]
    assert fake_redis.pubsub_instance.subscribed_channels == []


@pytest.mark.asyncio
async def test_listen_for_auth_reads_pubsub_message(monkeypatch):
    fake_pubsub = FakePubSub(
        messages=[
            {"type": "subscribe", "data": 1},
            {"type": "message", "data": json.dumps({"redirect_to": "https://hydra.example.com/live"})},
        ]
    )
    fake_redis = FakeRedis(pubsub=fake_pubsub)
    monkeypatch.setattr("lnurl_hydra_login.sse.aioredis.from_url", lambda *_args, **_kwargs: fake_redis)

    manager = RedisSseManager("redis://fake")
    results = [redirect async for redirect in manager.listen_for_auth("k1-123")]

    assert results == ["https://hydra.example.com/live"]
    assert fake_pubsub.subscribed_channels == ["lnurl:auth:k1-123"]
    assert fake_pubsub.closed is True


@pytest.mark.asyncio
async def test_listen_for_auth_times_out_and_closes_pubsub(monkeypatch):
    fake_pubsub = FakePubSub(hang=True)
    fake_redis = FakeRedis(pubsub=fake_pubsub)
    monkeypatch.setattr("lnurl_hydra_login.sse.aioredis.from_url", lambda *_args, **_kwargs: fake_redis)

    manager = RedisSseManager("redis://fake")
    results = [redirect async for redirect in manager.listen_for_auth("k1-123", timeout=0.01)]

    assert results == []
    assert fake_pubsub.subscribed_channels == ["lnurl:auth:k1-123"]
    assert fake_pubsub.closed is True
