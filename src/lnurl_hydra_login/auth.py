"""LNURL-auth challenge generation and signature verification."""

import logging
import secrets
import time

from lnurl import encode as lnurl_encode_lib
from lnurl.helpers import lnurlauth_verify

logger = logging.getLogger(__name__)


def lnurl_encode(url: str) -> str:
    return lnurl_encode_lib(url).bech32.lower()


async def generate_k1_challenge(db, login_challenge: str, config) -> tuple[str, str]:
    """Generate a k1 challenge, store it linked to the Hydra login_challenge."""
    k1_hex = secrets.token_bytes(32).hex()
    created_at = int(time.time())
    expires_at = created_at + config.auth_challenge_expiry_seconds

    await db.execute(
        """
        INSERT INTO auth_challenges (k1, login_challenge, created_at, expires_at)
        VALUES ($1, $2, $3, $4)
        """,
        k1_hex,
        login_challenge,
        created_at,
        expires_at,
    )

    callback_url = f"{config.lnurl_callback_url}?tag=login&k1={k1_hex}"
    return k1_hex, lnurl_encode(callback_url)


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


async def mark_challenge_used(db, k1: str) -> bool:
    """Atomically mark challenge as used. Returns False if already used."""
    result = await db.execute(
        "UPDATE auth_challenges SET used = 1 WHERE k1 = $1 AND used = 0",
        k1,
    )
    return int(result.split()[-1]) > 0 if result else False
