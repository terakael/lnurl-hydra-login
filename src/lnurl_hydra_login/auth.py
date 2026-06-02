"""LNURL-auth challenge generation and signature verification."""

import logging
import secrets
import time

from lnurl import encode as lnurl_encode_lib
from lnurl.helpers import lnurlauth_verify

logger = logging.getLogger(__name__)


def lnurl_encode(url: str) -> str:
    return lnurl_encode_lib(url).bech32.lower()


async def generate_k1_challenge(db, login_challenge: str, config) -> tuple[str, str, str, str]:
    """Generate a k1 challenge, store it linked to the Hydra login_challenge.

    Returns (k1_hex, lnurl_string, stream_token, session_id).

    stream_token: secret delivered as an HttpOnly cookie; authorises opening
    the SSE stream for this challenge.

    session_id: non-secret routing key embedded in the page JS; used only to
    name the right st_<session_id> cookie so multiple tabs don't collide.
    """
    k1_hex = secrets.token_bytes(32).hex()
    stream_token = secrets.token_urlsafe(32)
    session_id = secrets.token_urlsafe(16)
    created_at = int(time.time())
    expires_at = created_at + config.auth_challenge_expiry_seconds

    await db.execute(
        """
        INSERT INTO auth_challenges
            (k1, login_challenge, created_at, expires_at, stream_token, session_id)
        VALUES ($1, $2, $3, $4, $5, $6)
        """,
        k1_hex,
        login_challenge,
        created_at,
        expires_at,
        stream_token,
        session_id,
    )

    callback_url = f"{config.lnurl_callback_url}?tag=login&k1={k1_hex}"
    return k1_hex, lnurl_encode(callback_url), stream_token, session_id


async def verify_lnurl_signature(k1: str, sig: str, key: str) -> bool:
    try:
        return lnurlauth_verify(k1=k1, sig=sig, key=key)
    except Exception as e:
        logger.error("Signature verification failed: %s: %s", type(e).__name__, e)
        return False


async def cleanup_expired_challenges(db) -> int:
    result = await db.execute(
        "DELETE FROM auth_challenges WHERE expires_at < $1",
        int(time.time()),
    )
    return int(result.split()[-1]) if result else 0


_STATE_PENDING   = 0
_STATE_CLAIMED   = 1
_STATE_COMPLETED = 2


async def claim_challenge(db, k1: str, sig: str, key: str) -> dict | None:
    """Atomically move a challenge from pending → claimed.

    Locks the row, validates it is pending and unexpired, verifies the
    secp256k1 signature — all inside one transaction. Sets used=1 (claimed)
    on success. A bad signature or any failure rolls back, leaving the
    challenge pending so the wallet can retry.

    Returns the row dict on success, None on any failure.
    """
    async with db.transaction() as conn:
        row = await conn.fetchrow(
            "SELECT k1, used, expires_at, login_challenge "
            "FROM auth_challenges WHERE k1 = $1 FOR UPDATE",
            k1,
        )
        if not row:
            return None
        if row["used"] != _STATE_PENDING:
            return None
        if int(time.time()) > row["expires_at"]:
            return None
        if not await verify_lnurl_signature(k1, sig, key):
            return None
        await conn.execute(
            "UPDATE auth_challenges SET used = $2 WHERE k1 = $1",
            k1, _STATE_CLAIMED,
        )
        return dict(row)


async def unclaim_challenge(db, k1: str) -> None:
    """Move a challenge from claimed → pending after a Hydra failure.

    Allows the wallet to retry without requiring a new QR scan.
    """
    await db.execute(
        "UPDATE auth_challenges SET used = $2 WHERE k1 = $1 AND used = $3",
        k1, _STATE_PENDING, _STATE_CLAIMED,
    )


async def complete_challenge(db, k1: str, pubkey: str, redirect_to: str) -> bool:
    """Move a challenge from claimed → completed and persist the auth result.

    Called only after Hydra has successfully accepted the login. Returns
    False if the row was not in the claimed state (should not happen in
    normal flow; indicates a bug if it does).
    """
    result = await db.execute(
        """
        UPDATE auth_challenges
           SET used             = $2,
               pubkey           = $3,
               redirect_to      = $4,
               authenticated_at = $5
         WHERE k1   = $1
           AND used = $6
        """,
        k1,
        _STATE_COMPLETED,
        pubkey,
        redirect_to,
        int(time.time()),
        _STATE_CLAIMED,
    )
    return int(result.split()[-1]) > 0 if result else False
