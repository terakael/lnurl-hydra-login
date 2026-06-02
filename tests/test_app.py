from __future__ import annotations

import asyncio
import inspect
import re
import pytest


async def _valid_signature(*_args, **_kwargs) -> bool:
    return True


_LONG_HYDRA_CHALLENGE = "A" * 1140


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
async def test_login_rejects_invalid_login_challenge_format(app):
    async with app.test_app():
        client = app.test_client()
        response = await client.get("/login?login_challenge=bad/challenge")

    assert response.status_code == 400
    assert await response.get_json() == {"error": "Invalid login_challenge"}


@pytest.mark.asyncio
async def test_login_accepts_long_hydra_challenge(app, fake_hydra):
    fake_hydra.login_requests[_LONG_HYDRA_CHALLENGE] = {"skip": False}

    async with app.test_app():
        client = app.test_client()
        response = await client.get(f"/login?login_challenge={_LONG_HYDRA_CHALLENGE}")

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_login_returns_502_when_hydra_fetch_fails(app, fake_hydra):
    fake_hydra.login_errors["fetch-fail"] = RuntimeError("boom")

    async with app.test_app():
        client = app.test_client()
        response = await client.get("/login?login_challenge=fetch-fail")

    assert response.status_code == 502
    assert await response.get_json() == {"error": "Failed to fetch login request"}


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
async def test_login_skip_returns_500_for_suspicious_redirect(app, fake_hydra):
    fake_hydra.login_requests["skip-bad-redirect"] = {"skip": True, "subject": "pubkey-1"}
    fake_hydra.login_accept_redirects["skip-bad-redirect"] = "https://evil.example.com/bad"

    async with app.test_app():
        client = app.test_client()
        response = await client.get("/login?login_challenge=skip-bad-redirect")

    assert response.status_code == 500
    assert await response.get_json() == {"error": "Internal error"}


@pytest.mark.asyncio
async def test_login_skip_returns_500_when_accept_fails(app, fake_hydra):
    fake_hydra.login_requests["skip-accept-fail"] = {"skip": True, "subject": "pubkey-1"}
    fake_hydra.accept_login_errors["skip-accept-fail"] = RuntimeError("boom")

    async with app.test_app():
        client = app.test_client()
        response = await client.get("/login?login_challenge=skip-accept-fail")

    assert response.status_code == 500
    assert await response.get_json() == {"error": "Internal error"}


@pytest.mark.asyncio
async def test_login_returns_500_when_challenge_generation_fails(app, monkeypatch, fake_hydra):
    fake_hydra.login_requests["generate-fail"] = {"skip": False}
    async def raise_error(*_args, **_kwargs):
        raise RuntimeError("db down")
    monkeypatch.setattr("lnurl_hydra_login.app.generate_k1_challenge", raise_error)

    async with app.test_app():
        client = app.test_client()
        response = await client.get("/login?login_challenge=generate-fail")

    assert response.status_code == 500
    assert await response.get_json() == {"error": "Internal error"}


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
    assert response.headers["Cache-Control"] == "no-store, private"
    csp = response.headers["Content-Security-Policy"]
    assert "default-src 'none'" in csp

    cookie = response.headers["Set-Cookie"]
    assert f"st_{row['session_id']}=" in cookie
    assert "HttpOnly" in cookie
    assert "Secure" in cookie
    assert "SameSite=Strict" in cookie
    assert "Max-Age=300" in cookie
    assert "Path=/lnurl/stream" in cookie
    nonce_header = re.search(r"script-src 'nonce-([^']+)'", csp)
    nonce_body = re.search(r'<script nonce="([^"]+)">', body)
    assert nonce_header is not None
    assert nonce_body is not None
    assert nonce_header.group(1) == nonce_body.group(1)


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
async def test_consent_requires_challenge_param(app):
    async with app.test_app():
        client = app.test_client()
        response = await client.get("/consent")

    assert response.status_code == 400
    assert await response.get_json() == {"error": "Missing consent_challenge"}


@pytest.mark.asyncio
async def test_consent_rejects_invalid_challenge_format(app):
    async with app.test_app():
        client = app.test_client()
        response = await client.get("/consent?consent_challenge=bad/challenge")

    assert response.status_code == 400
    assert await response.get_json() == {"error": "Invalid consent_challenge"}


@pytest.mark.asyncio
async def test_consent_accepts_long_hydra_challenge(app, fake_hydra):
    fake_hydra.consent_requests[_LONG_HYDRA_CHALLENGE] = {
        "requested_scope": ["openid"],
        "subject": "pubkey-1",
    }

    async with app.test_app():
        client = app.test_client()
        response = await client.get(f"/consent?consent_challenge={_LONG_HYDRA_CHALLENGE}")

    assert response.status_code == 302


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
async def test_consent_accepts_empty_scope_list(app, fake_hydra):
    fake_hydra.consent_requests["consent-empty"] = {
        "requested_scope": [],
        "subject": "pubkey-1",
    }

    async with app.test_app():
        client = app.test_client()
        response = await client.get("/consent?consent_challenge=consent-empty")

    assert response.status_code == 302
    challenge, scopes, subject = fake_hydra.accept_consent_calls[0]
    assert challenge == "consent-empty"
    assert scopes == []
    assert subject == "pubkey-1"


@pytest.mark.asyncio
async def test_consent_returns_500_for_suspicious_redirect(app, fake_hydra):
    fake_hydra.consent_requests["consent-bad-redirect"] = {
        "requested_scope": ["openid"],
        "subject": "pubkey-1",
    }
    fake_hydra.consent_accept_redirects["consent-bad-redirect"] = "https://evil.example.com/consent"

    async with app.test_app():
        client = app.test_client()
        response = await client.get("/consent?consent_challenge=consent-bad-redirect")

    assert response.status_code == 500
    assert await response.get_json() == {"error": "Internal error"}


@pytest.mark.asyncio
async def test_consent_returns_500_when_hydra_errors(app, fake_hydra):
    fake_hydra.consent_errors["consent-fail"] = RuntimeError("boom")

    async with app.test_app():
        client = app.test_client()
        response = await client.get("/consent?consent_challenge=consent-fail")

    assert response.status_code == 500
    assert await response.get_json() == {"error": "Internal error"}


@pytest.mark.asyncio
async def test_consent_returns_500_when_accept_fails(app, fake_hydra):
    fake_hydra.consent_requests["consent-accept-fail"] = {
        "requested_scope": ["openid"],
        "subject": "pubkey-1",
    }
    fake_hydra.accept_consent_errors["consent-accept-fail"] = RuntimeError("boom")

    async with app.test_app():
        client = app.test_client()
        response = await client.get("/consent?consent_challenge=consent-accept-fail")

    assert response.status_code == 500
    assert await response.get_json() == {"error": "Internal error"}


@pytest.mark.asyncio
async def test_lnurl_callback_rejects_invalid_parameters(app):
    async with app.test_app():
        client = app.test_client()
        response = await client.get("/lnurl/callback?tag=login&k1=abc")

    assert response.status_code == 400
    assert await response.get_json() == {"status": "ERROR", "reason": "Invalid parameters"}


@pytest.mark.asyncio
async def test_lnurl_callback_rejects_wrong_tag(app):
    async with app.test_app():
        client = app.test_client()
        response = await client.get("/lnurl/callback?tag=withdraw&k1=abc&sig=sig&key=pubkey")

    assert response.status_code == 400
    assert await response.get_json() == {"status": "ERROR", "reason": "Invalid parameters"}


@pytest.mark.asyncio
async def test_lnurl_callback_rejects_missing_or_expired_challenge(app):
    async with app.test_app():
        client = app.test_client()
        response = await client.get(f"/lnurl/callback?tag=login&k1={'d'*64}&sig=sig&key=pubkey")

    assert response.status_code == 400
    assert await response.get_json() == {"status": "ERROR", "reason": "Invalid or expired challenge"}


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
async def test_lnurl_callback_unclaims_on_suspicious_redirect(app, fake_db, fake_hydra, clock, monkeypatch):
    k1 = "s" * 64
    fake_db.seed_challenge(k1=k1, login_challenge="login-bad-redirect", expires_at=clock.now + 60)
    fake_hydra.login_accept_redirects["login-bad-redirect"] = "https://evil.example.com/bad"
    monkeypatch.setattr("lnurl_hydra_login.auth.verify_lnurl_signature", _valid_signature)

    async with app.test_app():
        client = app.test_client()
        response = await client.get(f"/lnurl/callback?tag=login&k1={k1}&sig=sig&key=pubkey-1")

    assert response.status_code == 500
    assert await response.get_json() == {"status": "ERROR", "reason": "Internal error"}
    assert fake_db.rows[k1]["used"] == 0
    assert fake_db.rows[k1]["claim_token"] is None


@pytest.mark.asyncio
async def test_lnurl_callback_succeeds_when_redis_publish_fails(app, fake_db, fake_hydra, fake_sse, clock, monkeypatch):
    k1 = "r" * 64
    fake_db.seed_challenge(k1=k1, login_challenge="login-redis-fail", expires_at=clock.now + 60)
    fake_sse.publish_error = RuntimeError("redis down")
    monkeypatch.setattr("lnurl_hydra_login.auth.verify_lnurl_signature", _valid_signature)

    async with app.test_app():
        client = app.test_client()
        response = await client.get(f"/lnurl/callback?tag=login&k1={k1}&sig=sig&key=pubkey-1")

    assert response.status_code == 200
    assert await response.get_json() == {"status": "OK"}
    assert fake_db.rows[k1]["used"] == 2


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
async def test_stream_requires_session_id(app):
    async with app.test_app():
        client = app.test_client()
        response = await client.get("/lnurl/stream")

    assert response.status_code == 401
    assert await response.get_json() == {"error": "Missing session id"}


@pytest.mark.asyncio
async def test_stream_requires_stream_cookie(app):
    async with app.test_app():
        client = app.test_client()
        response = await client.get("/lnurl/stream?sid=sid-1")

    assert response.status_code == 401
    assert await response.get_json() == {"error": "Missing stream token"}


@pytest.mark.asyncio
async def test_stream_rejects_unknown_session(app):
    async with app.test_app():
        client = app.test_client()
        response = await client.get("/lnurl/stream?sid=missing", headers=_cookie_header("missing", "token"))

    assert response.status_code == 401
    assert await response.get_json() == {"error": "Invalid session"}


@pytest.mark.asyncio
async def test_stream_rejects_expired_session(app, fake_db, clock):
    fake_db.seed_challenge(
        k1="g" * 64,
        session_id="sid-expired",
        stream_token="token-expired",
        expires_at=clock.now - 1,
    )

    async with app.test_app():
        client = app.test_client()
        response = await client.get(
            "/lnurl/stream?sid=sid-expired",
            headers=_cookie_header("sid-expired", "token-expired"),
        )

    assert response.status_code == 410
    assert await response.get_json() == {"error": "Challenge expired"}


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
async def test_stream_emits_authenticated_event_from_redis_queue(app, fake_db, fake_sse, clock):
    redirect_to = "https://hydra.example.com/oauth2/auth?login_verifier=live"
    k1 = "h" * 64
    fake_db.seed_challenge(
        k1=k1,
        session_id="sid-live",
        stream_token="stream-live",
        expires_at=clock.now + 60,
    )
    fake_sse.listen_results[k1] = [redirect_to]

    async with app.test_app():
        client = app.test_client()
        response = await client.get(
            "/lnurl/stream?sid=sid-live",
            headers=_cookie_header("sid-live", "stream-live"),
        )
        body = await response.get_data(as_text=True)

    assert response.status_code == 200
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
async def test_stream_post_subscribe_db_recheck_finds_result(app, fake_db, fake_sse, clock, monkeypatch):
    redirect_to = "https://hydra.example.com/oauth2/auth?login_verifier=recheck"
    k1 = "k" * 64
    fake_db.seed_challenge(
        k1=k1,
        session_id="sid-recheck",
        stream_token="stream-recheck",
        expires_at=clock.now + 60,
    )
    fake_sse.listen_hooks[k1] = lambda: fake_db.rows[k1].update({"redirect_to": redirect_to})

    original_fetchrow = fake_db.fetchrow

    async def fetchrow_with_yield(query: str, *args):
        if "SELECT redirect_to FROM auth_challenges WHERE k1 = $1" in " ".join(query.split()):
            await asyncio.sleep(0)
        return await original_fetchrow(query, *args)

    monkeypatch.setattr(fake_db, "fetchrow", fetchrow_with_yield)

    async with app.test_app():
        client = app.test_client()
        response = await client.get(
            "/lnurl/stream?sid=sid-recheck",
            headers=_cookie_header("sid-recheck", "stream-recheck"),
        )
        body = await response.get_data(as_text=True)

    assert response.status_code == 200
    assert "event: authenticated" in body
    assert redirect_to in body


@pytest.mark.asyncio
async def test_stream_heartbeat_poll_finds_db_result(app, fake_db, fake_sse, clock, monkeypatch):
    redirect_to = "https://hydra.example.com/oauth2/auth?login_verifier=heartbeat"
    k1 = "i" * 64
    fake_db.seed_challenge(
        k1=k1,
        session_id="sid-heartbeat",
        stream_token="stream-heartbeat",
        expires_at=clock.now + 60,
    )

    real_wait_for = asyncio.wait_for

    class WaitForOnce:
        def __init__(self):
            self.heartbeat_calls = 0

        async def __call__(self, _awaitable, timeout):
            if timeout == 20:
                self.heartbeat_calls += 1
            if timeout == 20 and self.heartbeat_calls == 1:
                if inspect.iscoroutine(_awaitable):
                    _awaitable.close()
                fake_db.rows[k1]["redirect_to"] = redirect_to
                raise asyncio.TimeoutError()
            return await real_wait_for(_awaitable, timeout)

    async def hang(*_args, **_kwargs):
        await asyncio.sleep(3600)
        if False:
            yield None

    fake_sse.listen_for_auth = hang

    async with app.test_app():
        monkeypatch.setattr("lnurl_hydra_login.app.asyncio.wait_for", WaitForOnce())
        client = app.test_client()
        response = await client.get(
            "/lnurl/stream?sid=sid-heartbeat",
            headers=_cookie_header("sid-heartbeat", "stream-heartbeat"),
        )
        body = await response.get_data(as_text=True)

    assert response.status_code == 200
    assert "event: authenticated" in body
    assert redirect_to in body


@pytest.mark.asyncio
async def test_stream_listener_error_falls_back_to_expired(app, fake_db, fake_sse, clock):
    k1 = "j" * 64
    fake_db.seed_challenge(
        k1=k1,
        session_id="sid-error",
        stream_token="stream-error",
        expires_at=clock.now + 60,
    )
    fake_sse.listen_errors[k1] = RuntimeError("redis fail")

    async with app.test_app():
        client = app.test_client()
        response = await client.get(
            "/lnurl/stream?sid=sid-error",
            headers=_cookie_header("sid-error", "stream-error"),
        )
        body = await response.get_data(as_text=True)

    assert response.status_code == 200
    assert "event: expired" in body


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


@pytest.mark.asyncio
async def test_health_returns_ok(app):
    async with app.test_app():
        client = app.test_client()
        response = await client.get("/health")

    assert response.status_code == 200
    assert await response.get_json() == {"status": "ok"}
