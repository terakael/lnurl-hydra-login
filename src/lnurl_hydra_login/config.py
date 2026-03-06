import os
from dataclasses import dataclass


@dataclass
class Config:
    database_url: str
    redis_url: str
    hydra_admin_url: str
    # Public URL wallets call back to - must be HTTPS in production
    # e.g. https://auth.example.com/lnurl/callback
    lnurl_callback_url: str
    auth_challenge_expiry_seconds: int = 300

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            database_url=os.environ["DATABASE_URL"],
            redis_url=os.environ.get("REDIS_URL", "redis://localhost:6379"),
            hydra_admin_url=os.environ["HYDRA_ADMIN_URL"],
            lnurl_callback_url=os.environ["LNURL_CALLBACK_URL"],
            auth_challenge_expiry_seconds=int(
                os.environ.get("AUTH_CHALLENGE_EXPIRY_SECONDS", "300")
            ),
        )
