from __future__ import annotations

import httpx
import pytest

from lnurl_hydra_login.hydra import HydraClient


@pytest.mark.asyncio
async def test_hydra_client_methods_send_expected_requests(monkeypatch):
    created_clients: list[httpx.AsyncClient] = []
    seen_requests: list[httpx.Request] = []
    real_async_client = httpx.AsyncClient

    def handler(request: httpx.Request) -> httpx.Response:
        seen_requests.append(request)

        if request.url.path == "/admin/oauth2/auth/requests/login" and request.method == "GET":
            assert dict(request.url.params) == {"login_challenge": "login-123"}
            return httpx.Response(
                200,
                json={"skip": False, "subject": "subject-1"},
                request=request,
            )

        if request.url.path == "/admin/oauth2/auth/requests/login/accept" and request.method == "PUT":
            assert dict(request.url.params) == {"login_challenge": "login-123"}
            assert request.read() == b'{"subject":"subject-1","remember":false,"amr":["lnurl"]}'
            return httpx.Response(
                200,
                json={"redirect_to": "https://hydra.example.com/login/accepted"},
                request=request,
            )

        if request.url.path == "/admin/oauth2/auth/requests/login/reject" and request.method == "PUT":
            assert dict(request.url.params) == {"login_challenge": "login-123"}
            assert request.read() == b'{"error":"access_denied","error_description":"denied"}'
            return httpx.Response(
                200,
                json={"redirect_to": "https://hydra.example.com/login/rejected"},
                request=request,
            )

        if request.url.path == "/admin/oauth2/auth/requests/consent" and request.method == "GET":
            assert dict(request.url.params) == {"consent_challenge": "consent-123"}
            return httpx.Response(
                200,
                json={"requested_scope": ["openid", "email"], "subject": "subject-1"},
                request=request,
            )

        if request.url.path == "/admin/oauth2/auth/requests/consent/accept" and request.method == "PUT":
            assert dict(request.url.params) == {"consent_challenge": "consent-123"}
            assert request.read() == (
                b'{"grant_scope":["openid","email"],"remember":false,"session":{"id_token":'
                b'{"lightning_pubkey":"subject-1","email":"subject-1@lightning","email_verified":true,"name":"subject-1"}}}'
            )
            return httpx.Response(
                200,
                json={"redirect_to": "https://hydra.example.com/consent/accepted"},
                request=request,
            )

        raise AssertionError(f"Unhandled request: {request.method} {request.url}")

    def client_factory(*_args, **kwargs) -> httpx.AsyncClient:
        client = real_async_client(
            transport=httpx.MockTransport(handler),
            timeout=kwargs.get("timeout"),
        )
        created_clients.append(client)
        return client

    monkeypatch.setattr("lnurl_hydra_login.hydra.httpx.AsyncClient", client_factory)

    hydra = HydraClient("https://hydra.example.com/")

    login_request = await hydra.get_login_request("login-123")
    login_redirect = await hydra.accept_login("login-123", "subject-1")
    reject_redirect = await hydra.reject_login("login-123", "denied")
    consent_request = await hydra.get_consent_request("consent-123")
    consent_redirect = await hydra.accept_consent("consent-123", ["openid", "email"], "subject-1")

    assert login_request == {"skip": False, "subject": "subject-1"}
    assert login_redirect == "https://hydra.example.com/login/accepted"
    assert reject_redirect == "https://hydra.example.com/login/rejected"
    assert consent_request == {"requested_scope": ["openid", "email"], "subject": "subject-1"}
    assert consent_redirect == "https://hydra.example.com/consent/accepted"
    assert len(seen_requests) == 5

    await hydra.close()
    assert created_clients[0].is_closed is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status_code", "call"),
    [
        (404, lambda hydra: hydra.get_login_request("login-123")),
        (409, lambda hydra: hydra.accept_login("login-123", "subject-1")),
        (404, lambda hydra: hydra.reject_login("login-123", "denied")),
        (404, lambda hydra: hydra.get_consent_request("consent-123")),
        (409, lambda hydra: hydra.accept_consent("consent-123", ["openid"], "subject-1")),
    ],
    ids=[
        "get_login_request_404",
        "accept_login_409",
        "reject_login_404",
        "get_consent_request_404",
        "accept_consent_409",
    ],
)
async def test_hydra_client_raises_for_non_success(monkeypatch, status_code, call):
    real_async_client = httpx.AsyncClient

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json={"error": "boom"}, request=request)

    monkeypatch.setattr(
        "lnurl_hydra_login.hydra.httpx.AsyncClient",
        lambda *_args, **kwargs: real_async_client(
            transport=httpx.MockTransport(handler),
            timeout=kwargs.get("timeout"),
        ),
    )

    hydra = HydraClient("https://hydra.example.com")

    with pytest.raises(httpx.HTTPStatusError):
        await call(hydra)

    await hydra.close()
