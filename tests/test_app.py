from __future__ import annotations

import pytest


async def _valid_signature(*_args, **_kwargs) -> bool:
    return True


def _cookie_header(session_id: str, stream_token: str) -> dict[str, str]:
    return {"Cookie": f"st_{session_id}={stream_token}"}


@pytest.mark.asyncio
async def test_login_rejects_missing_login_challenge(app):
    async with app.test_app():
        client = app.test_client()
        response = await client.get("/login")

    assert response.status_code == 400
    assert await response.get_json() == {"error": "Missing login_challenge"}


@pytest.mark.asyncio
async def test_login_skip_accepts_existing_hydra_session(app, fake_db, fake_hydra):
    fake_hydra.login_requests["skip-challenge"] = {"skip": True, "subject": "pubkey-1"}

    async with app.test_app():
        client = app.test_client()
        response = await client.get("/login?login_challenge=skip-challenge")

    assert response.status_code == 302
    assert response.headers["Location"] == "https://hydra.example.com/oauth2/auth?login_verifier=skip-challenge"
    assert fake_hydra.accept_login_calls == [("skip-challenge", "pubkey-1")]
    assert fake_db.rows == {}


@pytest.mark.asyncio
async def test_login_renders_qr_and_sets_stream_cookie(app, fake_db, fake_hydra):
    fake_hydra.login_requests["fresh-challenge"] = {"skip": False}

    async with app.test_app():
        client = app.test_client()
        response = await client.get("/login?login_challenge=fresh-challenge")
        body = await response.get_data(as_text=True)

    assert response.status_code == 200
    assert fake_db.connected is True
    assert fake_db.migrate_calls == 1
    assert len(fake_db.rows) == 1

    row = next(iter(fake_db.rows.values()))
    assert row["login_challenge"] == "fresh-challenge"
    assert row["used"] == 0
    assert row["session_id"] in body
    assert "default-src 'none'" in response.headers["Content-Security-Policy"]

    cookie = response.headers["Set-Cookie"]
    assert f"st_{row['session_id']}=" in cookie
    assert "HttpOnly" in cookie
    assert "Path=/lnurl/stream" in cookie


@pytest.mark.asyncio
async def test_consent_rejects_disallowed_scopes(app, fake_hydra):
    fake_hydra.consent_requests["consent-1"] = {
        "requested_scope": ["openid", "admin"],
        "subject": "pubkey-1",
    }

    async with app.test_app():
        client = app.test_client()
        response = await client.get("/consent?consent_challenge=consent-1")

    assert response.status_code == 403
    assert await response.get_json() == {"error": "Requested scopes are not permitted"}
    assert fake_hydra.accept_consent_calls == []


@pytest.mark.asyncio
async def test_consent_accepts_allowed_scopes(app, fake_hydra):
    fake_hydra.consent_requests["consent-2"] = {
        "requested_scope": ["openid", "email"],
        "subject": "pubkey-1",
    }

    async with app.test_app():
        client = app.test_client()
        response = await client.get("/consent?consent_challenge=consent-2")

    assert response.status_code == 302
    assert response.headers["Location"] == "https://hydra.example.com/oauth2/auth?consent_verifier=consent-2"
    challenge, scopes, subject = fake_hydra.accept_consent_calls[0]
    assert challenge == "consent-2"
    assert set(scopes) == {"openid", "email"}
    assert subject == "pubkey-1"


@pytest.mark.asyncio
async def test_lnurl_callback_completes_challenge_and_publishes(app, fake_db, fake_hydra, fake_sse, clock, monkeypatch):
    k1 = "a" * 64
    fake_db.seed_challenge(k1=k1, login_challenge="login-1", expires_at=clock.now + 60)
    monkeypatch.setattr("lnurl_hydra_login.auth.verify_lnurl_signature", _valid_signature)

    async with app.test_app():
        client = app.test_client()
        response = await client.get(f"/lnurl/callback?tag=login&k1={k1}&sig=sig&key=pubkey-1")

    assert response.status_code == 200
    assert await response.get_json() == {"status": "OK"}
    assert fake_hydra.accept_login_calls == [("login-1", "pubkey-1")]
    assert fake_sse.published == [(k1, "https://hydra.example.com/oauth2/auth?login_verifier=login-1")]

    row = fake_db.rows[k1]
    assert row["used"] == 2
    assert row["pubkey"] == "pubkey-1"
    assert row["redirect_to"] == "https://hydra.example.com/oauth2/auth?login_verifier=login-1"
    assert row["authenticated_at"] == clock.now


@pytest.mark.asyncio
async def test_lnurl_callback_unclaims_when_hydra_accept_fails(app, fake_db, fake_hydra, clock, monkeypatch):
    k1 = "b" * 64
    fake_db.seed_challenge(k1=k1, login_challenge="login-2", expires_at=clock.now + 60)
    fake_hydra.accept_login_errors["login-2"] = RuntimeError("boom")
    monkeypatch.setattr("lnurl_hydra_login.auth.verify_lnurl_signature", _valid_signature)

    async with app.test_app():
        client = app.test_client()
        response = await client.get(f"/lnurl/callback?tag=login&k1={k1}&sig=sig&key=pubkey-2")

    assert response.status_code == 500
    assert await response.get_json() == {"status": "ERROR", "reason": "Internal error"}

    row = fake_db.rows[k1]
    assert row["used"] == 0
    assert row["claim_token"] is None
    assert row["claim_expires_at"] is None


@pytest.mark.asyncio
async def test_lnurl_callback_returns_500_if_claim_lease_is_lost_midflight(
    app, fake_db, fake_hydra, clock, monkeypatch
):
    k1 = "c" * 64
    fake_db.seed_challenge(k1=k1, login_challenge="login-3", expires_at=clock.now + 60)
    monkeypatch.setattr("lnurl_hydra_login.auth.verify_lnurl_signature", _valid_signature)

    async def lose_claim(_login_challenge: str, _subject: str) -> str:
        fake_db.rows[k1]["claim_token"] = "new-owner"
        fake_db.rows[k1]["claim_expires_at"] = clock.now + 30
        return "https://hydra.example.com/oauth2/auth?login_verifier=login-3"

    fake_hydra.on_accept_login = lose_claim

    async with app.test_app():
        client = app.test_client()
        response = await client.get(f"/lnurl/callback?tag=login&k1={k1}&sig=sig&key=pubkey-3")

    assert response.status_code == 500
    assert await response.get_json() == {"status": "ERROR", "reason": "Internal error"}
    assert fake_db.rows[k1]["used"] == 1
    assert fake_db.rows[k1]["claim_token"] == "new-owner"


@pytest.mark.asyncio
async def test_stream_requires_valid_stream_cookie(app, fake_db, clock):
    fake_db.seed_challenge(
        k1="d" * 64,
        session_id="sid-1",
        stream_token="correct-token",
        expires_at=clock.now + 60,
    )

    async with app.test_app():
        client = app.test_client()
        response = await client.get("/lnurl/stream?sid=sid-1", headers=_cookie_header("sid-1", "wrong-token"))

    assert response.status_code == 401
    assert await response.get_json() == {"error": "Invalid stream token"}


@pytest.mark.asyncio
async def test_stream_returns_authenticated_event_from_db(app, fake_db, clock):
    redirect_to = "https://hydra.example.com/oauth2/auth?login_verifier=done"
    fake_db.seed_challenge(
        k1="e" * 64,
        session_id="sid-2",
        stream_token="stream-2",
        expires_at=clock.now + 60,
        redirect_to=redirect_to,
    )

    async with app.test_app():
        client = app.test_client()
        response = await client.get("/lnurl/stream?sid=sid-2", headers=_cookie_header("sid-2", "stream-2"))
        body = await response.get_data(as_text=True)

    assert response.status_code == 200
    assert "event: connected" in body
    assert "event: authenticated" in body
    assert redirect_to in body


@pytest.mark.asyncio
async def test_stream_rechecks_db_after_subscribing(app, fake_db, fake_sse, clock):
    redirect_to = "https://hydra.example.com/oauth2/auth?login_verifier=late"
    k1 = "f" * 64
    fake_db.seed_challenge(
        k1=k1,
        session_id="sid-3",
        stream_token="stream-3",
        expires_at=clock.now + 60,
    )
    fake_sse.listen_hooks[k1] = lambda: fake_db.rows[k1].update({"redirect_to": redirect_to})

    async with app.test_app():
        client = app.test_client()
        response = await client.get("/lnurl/stream?sid=sid-3", headers=_cookie_header("sid-3", "stream-3"))
        body = await response.get_data(as_text=True)

    assert response.status_code == 200
    assert "event: authenticated" in body
    assert redirect_to in body


@pytest.mark.asyncio
async def test_stream_emits_expired_when_listener_finishes_without_result(app, fake_db, clock):
    fake_db.seed_challenge(
        k1="1" * 64,
        session_id="sid-4",
        stream_token="stream-4",
        expires_at=clock.now + 60,
    )

    async with app.test_app():
        client = app.test_client()
        response = await client.get("/lnurl/stream?sid=sid-4", headers=_cookie_header("sid-4", "stream-4"))
        body = await response.get_data(as_text=True)

    assert response.status_code == 200
    assert "event: expired" in body
