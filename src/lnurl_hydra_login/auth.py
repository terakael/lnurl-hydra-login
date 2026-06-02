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


_CLAIM_LEASE_SECONDS = 30


async def recover_stale_claims(db) -> int:
    """Reset claimed rows whose lease has expired back to pending.

    Safe to call from any replica at any time including startup. Only touches
    rows where claim_expires_at < now, so an active claim on another pod is
    never disturbed. claim_token + claim_expires_at act as a fencing token:
    if a row is recovered and re-claimed before the original pod's
    unclaim/complete runs, the WHERE clause on those calls matches zero rows
    and the stale write is silently discarded.
    """
    result = await db.execute(
        "UPDATE auth_challenges SET used = $1, claim_token = NULL, claim_expires_at = NULL "
        "WHERE used = $2 AND claim_expires_at < $3",
        _STATE_PENDING, _STATE_CLAIMED, int(time.time()),
    )
    count = int(result.split()[-1]) if result else 0
    if count:
        logger.warning("Recovered %d stale claimed challenge(s)", count)
    return count


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
    secp256k1 signature — all inside one transaction. Writes a claim_token
    (random fencing token) and claim_expires_at (lease TTL) so that
    recover_stale_claims() on any replica can only reset genuinely abandoned
    claims, and so that a slow pod's unclaim/complete is fenced out if the
    lease has already been recovered and re-claimed by another request.

    Returns the row dict (including claim_token) on success, None on any failure.
    """
    now = int(time.time())
    claim_token = secrets.token_hex(16)
    claim_expires_at = now + _CLAIM_LEASE_SECONDS
    async with db.transaction() as conn:
        row = await conn.fetchrow(
            "SELECT k1, used, expires_at, login_challenge, claim_expires_at "
            "FROM auth_challenges WHERE k1 = $1 FOR UPDATE",
            k1,
        )
        if not row:
            return None
        if now > row["expires_at"]:
            return None

        if row["used"] == _STATE_CLAIMED:
            # Another pod claimed this row but its lease has expired — the pod
            # that held the claim is gone. Recover inline under the row lock so
            # retries on any healthy replica succeed without waiting for startup.
            if row["claim_expires_at"] is None or now <= row["claim_expires_at"]:
                return None  # lease still valid; another pod is actively processing
            logger.warning("Recovering expired claim for k1=%.16s... inline", k1)
            # Fall through: write new claim below
        elif row["used"] != _STATE_PENDING:
            return None  # completed or unknown state

        if not await verify_lnurl_signature(k1, sig, key):
            return None
        await conn.execute(
            "UPDATE auth_challenges "
            "SET used = $2, claim_token = $3, claim_expires_at = $4 WHERE k1 = $1",
            k1, _STATE_CLAIMED, claim_token, claim_expires_at,
        )
        return {**dict(row), "claim_token": claim_token}


async def unclaim_challenge(db, k1: str, claim_token: str) -> None:
    """Move a challenge from claimed → pending after a Hydra failure.

    claim_token gates the write: if the lease was already recovered and
    re-claimed by another request, the WHERE clause matches zero rows and
    this stale unclaim is silently discarded.
    """
    await db.execute(
        "UPDATE auth_challenges "
        "SET used = $2, claim_token = NULL, claim_expires_at = NULL "
        "WHERE k1 = $1 AND used = $3 AND claim_token = $4",
        k1, _STATE_PENDING, _STATE_CLAIMED, claim_token,
    )


async def complete_challenge(db, k1: str, pubkey: str, redirect_to: str, claim_token: str) -> bool:
    """Move a challenge from claimed → completed and persist the auth result.

    claim_token gates the write: if the lease was already recovered and
    re-claimed by another request, the WHERE clause matches zero rows and
    this stale complete is silently discarded (returns False).
    """
    result = await db.execute(
        """
        UPDATE auth_challenges
           SET used             = $2,
               pubkey           = $3,
               redirect_to      = $4,
               authenticated_at = $5,
               claim_token      = NULL,
               claim_expires_at = NULL
         WHERE k1          = $1
           AND used         = $6
           AND claim_token  = $7
        """,
        k1,
        _STATE_COMPLETED,
        pubkey,
        redirect_to,
        int(time.time()),
        _STATE_CLAIMED,
        claim_token,
    )
    return int(result.split()[-1]) > 0 if result else False
