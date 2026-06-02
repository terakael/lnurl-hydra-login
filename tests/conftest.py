from __future__ import annotations

import pytest
from pytest_postgresql.factories import postgresql as postgresql_factory
from pytest_postgresql.factories import postgresql_proc as postgresql_proc_factory

from lnurl_hydra_login.app import create_app
from lnurl_hydra_login.config import Config

from tests.fakes import FakeDatabase, FakeHydra, FakeSseManager


postgresql_proc = postgresql_proc_factory(port=15432)
postgresql = postgresql_factory("postgresql_proc")


class FrozenClock:
    def __init__(self, now: int = 1_700_000_000):
        self.now = now

    def time(self) -> int:
        return self.now

    def set(self, value: int) -> None:
        self.now = value

    def tick(self, seconds: int) -> None:
        self.now += seconds


@pytest.fixture
def clock(monkeypatch):
    frozen = FrozenClock()
    monkeypatch.setattr("lnurl_hydra_login.auth.time.time", frozen.time)
    monkeypatch.setattr("lnurl_hydra_login.app.time.time", frozen.time)
    return frozen


@pytest.fixture
def config():
    return Config(
        database_url="postgresql://fake/fake",
        redis_url="redis://fake/0",
        hydra_admin_url="http://hydra:4445",
        hydra_public_url="https://hydra.example.com",
        lnurl_callback_url="https://login.example.com/lnurl/callback",
        auth_challenge_expiry_seconds=300,
        secure_cookies=True,
    )


@pytest.fixture
def fake_db():
    return FakeDatabase()


@pytest.fixture
def fake_hydra(config):
    return FakeHydra(config.hydra_public_url)


@pytest.fixture
def fake_sse():
    return FakeSseManager()


@pytest.fixture
def app(config, fake_db, fake_hydra, fake_sse, clock):
    return create_app(config, db=fake_db, hydra=fake_hydra, sse=fake_sse)
