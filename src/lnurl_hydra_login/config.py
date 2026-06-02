import os
from dataclasses import dataclass, field


@dataclass
class Config:
    database_url: str
    redis_url: str
    hydra_admin_url: str
    # Public-facing Hydra URL (e.g. https://hydra.example.com). Used to
    # validate that redirect_to URLs returned by Hydra stay on-origin.
    hydra_public_url: str
    # Public URL wallets call back to - must be HTTPS in production
    # e.g. https://auth.example.com/lnurl/callback
    lnurl_callback_url: str
    auth_challenge_expiry_seconds: int = 300
    # Set False only for local HTTP dev (SECURE_COOKIES=false). Always True in prod.
    secure_cookies: bool = True
    # Scopes auto-approved without a user consent screen. Extend via env var
    # CONSENT_ALLOWED_SCOPES as a comma-separated list.
    consent_allowed_scopes: frozenset = field(
        default_factory=lambda: frozenset({"openid", "offline", "offline_access", "email", "profile"})
    )

    @classmethod
    def from_env(cls) -> "Config":
        raw_scopes = os.environ.get("CONSENT_ALLOWED_SCOPES", "")
        if raw_scopes.strip():
            scopes = frozenset(s.strip() for s in raw_scopes.split(",") if s.strip())
        else:
            scopes = frozenset({"openid", "offline", "offline_access", "email", "profile"})
        return cls(
            database_url=os.environ["DATABASE_URL"],
            redis_url=os.environ.get("REDIS_URL", "redis://localhost:6379"),
            hydra_admin_url=os.environ["HYDRA_ADMIN_URL"],
            hydra_public_url=os.environ["HYDRA_PUBLIC_URL"].rstrip("/"),
            lnurl_callback_url=os.environ["LNURL_CALLBACK_URL"],
            auth_challenge_expiry_seconds=int(
                os.environ.get("AUTH_CHALLENGE_EXPIRY_SECONDS", "300")
            ),
            secure_cookies=os.environ.get("SECURE_COOKIES", "true").lower() != "false",
            consent_allowed_scopes=scopes,
        )
