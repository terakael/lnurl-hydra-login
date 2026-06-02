from __future__ import annotations

import pytest

from lnurl_hydra_login.auth import (
    claim_challenge,
    cleanup_expired_challenges,
    complete_challenge,
    recover_stale_claims,
    unclaim_challenge,
    verify_lnurl_signature,
)


async def _valid_signature(*_args, **_kwargs) -> bool:
    return True


@pytest.mark.asyncio
async def test_verify_lnurl_signature_returns_false_on_verifier_exception(monkeypatch):
    def raise_error(**_kwargs):
        raise ValueError("bad sig")

    monkeypatch.setattr("lnurl_hydra_login.auth.lnurlauth_verify", raise_error)

    assert await verify_lnurl_signature("k1", "sig", "pubkey") is False


@pytest.mark.asyncio
async def test_claim_challenge_claims_pending_row(fake_db, clock, monkeypatch):
    k1 = "a" * 64
    fake_db.seed_challenge(k1=k1, expires_at=clock.now + 60)
    monkeypatch.setattr("lnurl_hydra_login.auth.verify_lnurl_signature", _valid_signature)

    row = await claim_challenge(fake_db, k1, "sig", "pubkey")

    assert row is not None
    assert row["k1"] == k1
    assert fake_db.rows[k1]["used"] == 1
    assert fake_db.rows[k1]["claim_token"]
    assert fake_db.rows[k1]["claim_expires_at"] == clock.now + 30


@pytest.mark.asyncio
async def test_claim_challenge_rejects_active_claim(fake_db, clock, monkeypatch):
    k1 = "b" * 64
    fake_db.seed_challenge(k1=k1, used=1, claim_token="active", claim_expires_at=clock.now + 10)
    monkeypatch.setattr("lnurl_hydra_login.auth.verify_lnurl_signature", _valid_signature)

    row = await claim_challenge(fake_db, k1, "sig", "pubkey")

    assert row is None
    assert fake_db.rows[k1]["claim_token"] == "active"


@pytest.mark.asyncio
async def test_claim_challenge_returns_none_for_missing_row(fake_db, monkeypatch):
    monkeypatch.setattr("lnurl_hydra_login.auth.verify_lnurl_signature", _valid_signature)

    row = await claim_challenge(fake_db, "missing" * 10 + "miss", "sig", "pubkey")

    assert row is None


@pytest.mark.asyncio
async def test_claim_challenge_rejects_expired_row(fake_db, clock, monkeypatch):
    k1 = "x" * 64
    fake_db.seed_challenge(k1=k1, expires_at=clock.now - 1)
    monkeypatch.setattr("lnurl_hydra_login.auth.verify_lnurl_signature", _valid_signature)

    row = await claim_challenge(fake_db, k1, "sig", "pubkey")

    assert row is None
    assert fake_db.rows[k1]["used"] == 0


@pytest.mark.asyncio
async def test_claim_challenge_recovers_expired_claim(fake_db, clock, monkeypatch):
    k1 = "c" * 64
    fake_db.seed_challenge(k1=k1, used=1, claim_token="stale", claim_expires_at=clock.now - 1)
    monkeypatch.setattr("lnurl_hydra_login.auth.verify_lnurl_signature", _valid_signature)

    row = await claim_challenge(fake_db, k1, "sig", "pubkey")

    assert row is not None
    assert fake_db.rows[k1]["used"] == 1
    assert fake_db.rows[k1]["claim_token"] != "stale"


@pytest.mark.asyncio
async def test_claim_challenge_rejects_completed_row(fake_db, clock, monkeypatch):
    k1 = "y" * 64
    fake_db.seed_challenge(k1=k1, used=2, expires_at=clock.now + 60)
    monkeypatch.setattr("lnurl_hydra_login.auth.verify_lnurl_signature", _valid_signature)

    row = await claim_challenge(fake_db, k1, "sig", "pubkey")

    assert row is None
    assert fake_db.rows[k1]["used"] == 2


@pytest.mark.asyncio
async def test_claim_challenge_rejects_bad_signature(fake_db, clock, monkeypatch):
    k1 = "z" * 64
    fake_db.seed_challenge(k1=k1, expires_at=clock.now + 60)

    async def _invalid_signature(*_args, **_kwargs) -> bool:
        return False

    monkeypatch.setattr("lnurl_hydra_login.auth.verify_lnurl_signature", _invalid_signature)

    row = await claim_challenge(fake_db, k1, "sig", "pubkey")

    assert row is None
    assert fake_db.rows[k1]["used"] == 0
    assert fake_db.rows[k1]["claim_token"] is None


@pytest.mark.asyncio
async def test_unclaim_challenge_is_fenced_by_claim_token(fake_db):
    k1 = "d" * 64
    fake_db.seed_challenge(k1=k1, used=1, claim_token="fresh", claim_expires_at=1_700_000_030)

    await unclaim_challenge(fake_db, k1, "stale")
    assert fake_db.rows[k1]["used"] == 1

    await unclaim_challenge(fake_db, k1, "fresh")
    assert fake_db.rows[k1]["used"] == 0
    assert fake_db.rows[k1]["claim_token"] is None


@pytest.mark.asyncio
async def test_complete_challenge_is_fenced_by_claim_token(fake_db, clock):
    k1 = "e" * 64
    fake_db.seed_challenge(k1=k1, used=1, claim_token="fresh", claim_expires_at=clock.now + 30)

    completed = await complete_challenge(fake_db, k1, "pubkey", "https://hydra.example.com/done", "stale")
    assert completed is False
    assert fake_db.rows[k1]["used"] == 1

    completed = await complete_challenge(fake_db, k1, "pubkey", "https://hydra.example.com/done", "fresh")
    assert completed is True
    assert fake_db.rows[k1]["used"] == 2
    assert fake_db.rows[k1]["pubkey"] == "pubkey"
    assert fake_db.rows[k1]["redirect_to"] == "https://hydra.example.com/done"
    assert fake_db.rows[k1]["authenticated_at"] == clock.now


@pytest.mark.asyncio
async def test_recover_stale_claims_resets_only_expired_claims(fake_db, clock):
    fake_db.seed_challenge(k1="f" * 64, used=1, claim_token="stale", claim_expires_at=clock.now - 1)
    fake_db.seed_challenge(k1="1" * 64, used=1, claim_token="active", claim_expires_at=clock.now + 1)
    fake_db.seed_challenge(k1="2" * 64, used=0)

    count = await recover_stale_claims(fake_db)

    assert count == 1
    assert fake_db.rows["f" * 64]["used"] == 0
    assert fake_db.rows["1" * 64]["used"] == 1
    assert fake_db.rows["2" * 64]["used"] == 0


@pytest.mark.asyncio
async def test_cleanup_expired_challenges_deletes_only_expired_rows(fake_db, clock):
    fake_db.seed_challenge(k1="3" * 64, expires_at=clock.now - 1)
    fake_db.seed_challenge(k1="4" * 64, expires_at=clock.now + 1)

    count = await cleanup_expired_challenges(fake_db)

    assert count == 1
    assert "3" * 64 not in fake_db.rows
    assert "4" * 64 in fake_db.rows
