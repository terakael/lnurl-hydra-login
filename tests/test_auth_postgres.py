from __future__ import annotations

import asyncio

import pytest

from lnurl_hydra_login.auth import (
    claim_challenge,
    cleanup_expired_challenges,
    complete_challenge,
    recover_stale_claims,
    unclaim_challenge,
)
from lnurl_hydra_login.db import Database


async def _valid_signature(*_args, **_kwargs) -> bool:
    return True


@pytest.fixture
async def pg_db(request):
    try:
        postgresql = request.getfixturevalue("postgresql")
        postgresql_proc = request.getfixturevalue("postgresql_proc")
    except Exception as exc:
        pytest.skip(f"pytest-postgresql unavailable in this environment: {type(exc).__name__}: {exc}")

    dbname = postgresql.info.dbname
    auth = postgresql_proc.user
    if postgresql_proc.password:
        auth = f"{auth}:{postgresql_proc.password}"
    database_url = f"postgresql://{auth}@{postgresql_proc.host}:{postgresql_proc.port}/{dbname}"

    db = Database(database_url)
    await db.connect()
    await db.migrate()
    try:
        yield db
    finally:
        await db.close()


async def _insert_challenge(
    db: Database,
    *,
    k1: str,
    login_challenge: str = "login-challenge",
    created_at: int = 1_700_000_000,
    expires_at: int = 1_700_000_300,
    used: int = 0,
    stream_token: str = "stream-token",
    session_id: str = "session-id",
    redirect_to: str | None = None,
    authenticated_at: int | None = None,
    pubkey: str | None = None,
    claim_token: str | None = None,
    claim_expires_at: int | None = None,
) -> None:
    await db.execute(
        """
        INSERT INTO auth_challenges
            (k1, login_challenge, created_at, expires_at, used, stream_token, session_id,
             redirect_to, authenticated_at, pubkey, claim_token, claim_expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        """,
        k1,
        login_challenge,
        created_at,
        expires_at,
        used,
        stream_token,
        session_id,
        redirect_to,
        authenticated_at,
        pubkey,
        claim_token,
        claim_expires_at,
    )


@pytest.mark.asyncio
async def test_database_migrate_is_idempotent_on_postgres(pg_db):
    await pg_db.migrate()

    used_constraint = await pg_db.fetchval(
        """
        SELECT pg_get_constraintdef(oid)
        FROM pg_constraint
        WHERE conname = 'auth_challenges_used_check'
        """
    )
    claim_token_exists = await pg_db.fetchval(
        """
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_name = 'auth_challenges'
              AND column_name = 'claim_token'
        )
        """
    )

    normalized_constraint = used_constraint.replace(" ", "")
    assert "used=ANY(ARRAY[0,1,2])" in normalized_constraint or "usedIN(0,1,2)" in normalized_constraint
    assert claim_token_exists is True


@pytest.mark.asyncio
async def test_claim_and_complete_round_trip_on_postgres(pg_db, clock, monkeypatch):
    k1 = "a" * 64
    await _insert_challenge(pg_db, k1=k1, expires_at=clock.now + 60)
    monkeypatch.setattr("lnurl_hydra_login.auth.verify_lnurl_signature", _valid_signature)

    row = await claim_challenge(pg_db, k1, "sig", "pubkey-1")
    assert row is not None

    completed = await complete_challenge(
        pg_db,
        k1,
        "pubkey-1",
        "https://hydra.example.com/oauth2/auth?login_verifier=done",
        row["claim_token"],
    )
    assert completed is True

    stored = await pg_db.fetchrow(
        """
        SELECT used, pubkey, redirect_to, authenticated_at, claim_token, claim_expires_at
        FROM auth_challenges
        WHERE k1 = $1
        """,
        k1,
    )
    assert stored["used"] == 2
    assert stored["pubkey"] == "pubkey-1"
    assert stored["redirect_to"] == "https://hydra.example.com/oauth2/auth?login_verifier=done"
    assert stored["authenticated_at"] == clock.now
    assert stored["claim_token"] is None
    assert stored["claim_expires_at"] is None


@pytest.mark.asyncio
async def test_claim_challenge_allows_only_one_concurrent_claimer_on_postgres(pg_db, clock, monkeypatch):
    k1 = "0" * 64
    await _insert_challenge(pg_db, k1=k1, expires_at=clock.now + 60)

    async def slow_valid_signature(*_args, **_kwargs) -> bool:
        await asyncio.sleep(0.05)
        return True

    monkeypatch.setattr("lnurl_hydra_login.auth.verify_lnurl_signature", slow_valid_signature)

    first, second = await asyncio.gather(
        claim_challenge(pg_db, k1, "sig", "pubkey-1"),
        claim_challenge(pg_db, k1, "sig", "pubkey-1"),
    )

    successful = [row for row in (first, second) if row is not None]
    assert len(successful) == 1
    assert sum(row is None for row in (first, second)) == 1

    stored = await pg_db.fetchrow(
        "SELECT used, claim_token, claim_expires_at FROM auth_challenges WHERE k1 = $1",
        k1,
    )
    assert stored["used"] == 1
    assert stored["claim_token"] == successful[0]["claim_token"]
    assert stored["claim_expires_at"] == clock.now + 30


@pytest.mark.asyncio
async def test_claim_rejects_active_lease_on_postgres(pg_db, clock, monkeypatch):
    k1 = "b" * 64
    await _insert_challenge(
        pg_db,
        k1=k1,
        used=1,
        expires_at=clock.now + 60,
        claim_token="active-token",
        claim_expires_at=clock.now + 10,
    )
    monkeypatch.setattr("lnurl_hydra_login.auth.verify_lnurl_signature", _valid_signature)

    row = await claim_challenge(pg_db, k1, "sig", "pubkey-2")

    assert row is None
    stored = await pg_db.fetchrow(
        "SELECT used, claim_token FROM auth_challenges WHERE k1 = $1",
        k1,
    )
    assert stored["used"] == 1
    assert stored["claim_token"] == "active-token"


@pytest.mark.asyncio
async def test_unclaim_and_complete_are_fenced_on_postgres(pg_db, clock):
    k1 = "c" * 64
    await _insert_challenge(
        pg_db,
        k1=k1,
        used=1,
        expires_at=clock.now + 60,
        claim_token="fresh-token",
        claim_expires_at=clock.now + 30,
    )

    await unclaim_challenge(pg_db, k1, "stale-token")
    still_claimed = await pg_db.fetchrow(
        "SELECT used, claim_token FROM auth_challenges WHERE k1 = $1",
        k1,
    )
    assert still_claimed["used"] == 1
    assert still_claimed["claim_token"] == "fresh-token"

    completed = await complete_challenge(
        pg_db,
        k1,
        "pubkey-3",
        "https://hydra.example.com/oauth2/auth?login_verifier=fenced",
        "stale-token",
    )
    assert completed is False

    await unclaim_challenge(pg_db, k1, "fresh-token")
    unclaimed = await pg_db.fetchrow(
        "SELECT used, claim_token, claim_expires_at FROM auth_challenges WHERE k1 = $1",
        k1,
    )
    assert unclaimed["used"] == 0
    assert unclaimed["claim_token"] is None
    assert unclaimed["claim_expires_at"] is None


@pytest.mark.asyncio
async def test_recover_and_cleanup_on_postgres(pg_db, clock):
    stale_k1 = "d" * 64
    active_k1 = "e" * 64
    expired_k1 = "f" * 64
    await _insert_challenge(
        pg_db,
        k1=stale_k1,
        used=1,
        expires_at=clock.now + 60,
        claim_token="stale",
        claim_expires_at=clock.now - 1,
    )
    await _insert_challenge(
        pg_db,
        k1=active_k1,
        used=1,
        expires_at=clock.now + 60,
        claim_token="active",
        claim_expires_at=clock.now + 10,
    )
    await _insert_challenge(
        pg_db,
        k1=expired_k1,
        expires_at=clock.now - 1,
    )

    recovered = await recover_stale_claims(pg_db)
    deleted = await cleanup_expired_challenges(pg_db)

    assert recovered == 1
    assert deleted == 1

    stale_row = await pg_db.fetchrow(
        "SELECT used, claim_token, claim_expires_at FROM auth_challenges WHERE k1 = $1",
        stale_k1,
    )
    active_row = await pg_db.fetchrow(
        "SELECT used, claim_token FROM auth_challenges WHERE k1 = $1",
        active_k1,
    )
    expired_row = await pg_db.fetchrow(
        "SELECT k1 FROM auth_challenges WHERE k1 = $1",
        expired_k1,
    )

    assert stale_row["used"] == 0
    assert stale_row["claim_token"] is None
    assert stale_row["claim_expires_at"] is None
    assert active_row["used"] == 1
    assert active_row["claim_token"] == "active"
    assert expired_row is None
