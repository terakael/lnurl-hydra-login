import logging

import httpx

logger = logging.getLogger(__name__)


class HydraClient:
    def __init__(self, admin_url: str):
        self._admin_url = admin_url.rstrip("/")
        self._client = httpx.AsyncClient(timeout=10.0)

    async def close(self):
        await self._client.aclose()

    async def get_login_request(self, login_challenge: str) -> dict:
        resp = await self._client.get(
            f"{self._admin_url}/admin/oauth2/auth/requests/login",
            params={"login_challenge": login_challenge},
        )
        resp.raise_for_status()
        return resp.json()

    async def accept_login(self, login_challenge: str, subject: str) -> str:
        resp = await self._client.put(
            f"{self._admin_url}/admin/oauth2/auth/requests/login/accept",
            params={"login_challenge": login_challenge},
            json={
                "subject": subject,
                "remember": True,
                "remember_for": 86400,
                "amr": ["lnurl"],
            },
        )
        resp.raise_for_status()
        return resp.json()["redirect_to"]

    async def reject_login(self, login_challenge: str, reason: str) -> str:
        resp = await self._client.put(
            f"{self._admin_url}/admin/oauth2/auth/requests/login/reject",
            params={"login_challenge": login_challenge},
            json={
                "error": "access_denied",
                "error_description": reason,
            },
        )
        resp.raise_for_status()
        return resp.json()["redirect_to"]

    async def get_consent_request(self, consent_challenge: str) -> dict:
        resp = await self._client.get(
            f"{self._admin_url}/admin/oauth2/auth/requests/consent",
            params={"consent_challenge": consent_challenge},
        )
        resp.raise_for_status()
        return resp.json()

    async def accept_consent(
        self, consent_challenge: str, grant_scope: list[str], subject: str
    ) -> str:
        resp = await self._client.put(
            f"{self._admin_url}/admin/oauth2/auth/requests/consent/accept",
            params={"consent_challenge": consent_challenge},
            json={
                "grant_scope": grant_scope,
                "remember": True,
                "remember_for": 86400,
                "session": {
                    "id_token": {
                        "lightning_pubkey": subject,
                    }
                },
            },
        )
        resp.raise_for_status()
        return resp.json()["redirect_to"]
