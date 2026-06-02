from __future__ import annotations

import pytest

from lnurl_hydra_login.app import _validate_redirect_to
from lnurl_hydra_login.config import Config


def test_validate_redirect_to_allows_same_origin():
    assert _validate_redirect_to(
        "https://hydra.example.com/oauth2/auth?foo=bar",
        "https://hydra.example.com",
    ) is True


def test_validate_redirect_to_rejects_mismatched_origin():
    assert _validate_redirect_to(
        "https://evil.example.com/oauth2/auth",
        "https://hydra.example.com",
    ) is False


def test_validate_redirect_to_rejects_scheme_mismatch():
    assert _validate_redirect_to(
        "http://hydra.example.com/oauth2/auth",
        "https://hydra.example.com",
    ) is False


def test_validate_redirect_to_rejects_relative_url():
    assert _validate_redirect_to(
        "/oauth2/auth?login_verifier=abc",
        "https://hydra.example.com",
    ) is False


def test_validate_redirect_to_rejects_control_characters():
    assert _validate_redirect_to(
        "https://hydra.example.com/oauth2/auth\nhttps://evil.example.com",
        "https://hydra.example.com",
    ) is False


@pytest.mark.parametrize("bad_char", ["\r", "\x00"])
def test_validate_redirect_to_rejects_other_control_characters(bad_char):
    assert _validate_redirect_to(
        f"https://hydra.example.com/oauth2/auth{bad_char}https://evil.example.com",
        "https://hydra.example.com",
    ) is False


def test_config_from_env_uses_defaults(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://db")
    monkeypatch.setenv("HYDRA_ADMIN_URL", "http://hydra:4445")
    monkeypatch.setenv("HYDRA_PUBLIC_URL", "https://hydra.example.com/")
    monkeypatch.setenv("LNURL_CALLBACK_URL", "https://login.example.com/lnurl/callback")
    monkeypatch.delenv("CONSENT_ALLOWED_SCOPES", raising=False)
    monkeypatch.delenv("SECURE_COOKIES", raising=False)

    config = Config.from_env()

    assert config.hydra_public_url == "https://hydra.example.com"
    assert config.secure_cookies is True
    assert config.consent_allowed_scopes == frozenset(
        {"openid", "offline", "offline_access", "email", "profile"}
    )


def test_config_from_env_parses_custom_scopes(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://db")
    monkeypatch.setenv("HYDRA_ADMIN_URL", "http://hydra:4445")
    monkeypatch.setenv("HYDRA_PUBLIC_URL", "https://hydra.example.com")
    monkeypatch.setenv("LNURL_CALLBACK_URL", "https://login.example.com/lnurl/callback")
    monkeypatch.setenv("CONSENT_ALLOWED_SCOPES", "openid, profile ,custom")
    monkeypatch.setenv("SECURE_COOKIES", "false")

    config = Config.from_env()

    assert config.secure_cookies is False
    assert config.consent_allowed_scopes == frozenset({"openid", "profile", "custom"})
