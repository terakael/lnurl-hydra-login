"""LNURL-auth challenge generation and signature verification."""

import logging
import secrets
import time

from lnurl import encode as lnurl_encode_lib
from lnurl.helpers import lnurlauth_verify

logger = logging.getLogger(__name__)


def lnurl_encode(url: str) -> str:
    return lnurl_encode_lib(url).bech32.lower()


async def generate_k1_challenge(db, login_challenge: str, config) -> tuple[str, str, str]:
    """Generate a k1 challenge, store it linked to the Hydra login_challenge.

    Returns (k1_hex, lnurl_string, stream_token). The stream_token is a separate
    secret that must be presented to open the SSE stream, so an observer who sees
    k1 in a URL or log cannot subscribe to the auth result.
    """
    k1_hex = secrets.token_bytes(32).hex()
    stream_token = secrets.token_urlsafe(32)
    created_at = int(time.time())
    expires_at = created_at + config.auth_challenge_expiry_seconds

    await db.execute(
        """
        INSERT INTO auth_challenges (k1, login_challenge, created_at, expires_at, stream_token)
        VALUES ($1, $2, $3, $4, $5)
        """,
        k1_hex,
        login_challenge,
        created_at,
        expires_at,
        stream_token,
    )

    callback_url = f"{config.lnurl_callback_url}?tag=login&k1={k1_hex}"
    return k1_hex, lnurl_encode(callback_url), stream_token


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


async def claim_and_verify_challenge(db, k1: str, sig: str, key: str) -> dict | None:
    """Validate, verify the signature, and atomically claim a challenge.

    All three steps happen inside a single transaction while the row lock is
    held: validate → verify signature → mark used. The UPDATE only commits if
    the signature is valid, so a bogus callback cannot burn a k1 before the
    real wallet uses it.

    Returns the row dict on success, or None if the challenge is invalid,
    expired, already used, or the signature fails verification.
    """
    async with db.transaction() as conn:
        row = await conn.fetchrow(
            "SELECT k1, used, expires_at, login_challenge "
            "FROM auth_challenges WHERE k1 = $1 FOR UPDATE",
            k1,
        )
        if not row:
            return None
        if row["used"]:
            return None
        if int(time.time()) > row["expires_at"]:
            return None
        # Verify inside the transaction so a bad sig causes a rollback,
        # leaving used=0 and allowing the real wallet to proceed.
        if not await verify_lnurl_signature(k1, sig, key):
            return None
        await conn.execute(
            "UPDATE auth_challenges SET used = 1 WHERE k1 = $1",
            k1,
        )
        return dict(row)
