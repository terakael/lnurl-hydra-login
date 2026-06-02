import asyncio
import base64
import contextlib
import hmac
import json
import logging
import os
import re
import time
import urllib.parse

from quart import Quart, Response, jsonify, make_response, redirect, render_template, request

from .auth import (
    claim_challenge,
    cleanup_expired_challenges,
    complete_challenge,
    generate_k1_challenge,
    lnurl_encode,
    recover_stale_claims,
    unclaim_challenge,
)
from .config import Config
from .db import Database
from .hydra import HydraClient
from .qr_utils import generate_qr_b64
from .sse import RedisSseManager

logger = logging.getLogger(__name__)


def _sse_event(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


# Hydra challenge tokens are opaque strings. The only guarantees from Hydra's
# source are that they're URL-safe and reasonably short. We accept a broad
# safe-character set rather than assuming a specific encoding.
_HYDRA_CHALLENGE_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,256}$")


def _validate_redirect_to(redirect_to: str, hydra_public_url: str) -> bool:
    """Return True only if redirect_to originates from the expected Hydra host."""
    if any(c in redirect_to for c in ("\n", "\r", "\x00")):
        return False
    try:
        parsed = urllib.parse.urlparse(redirect_to)
    except Exception:
        return False
    if not parsed.scheme or not parsed.netloc:
        return False
    # Strip path/query from hydra_public_url to get the bare origin for comparison
    expected = urllib.parse.urlparse(hydra_public_url)
    return parsed.scheme == expected.scheme and parsed.netloc == expected.netloc


def create_app(config: Config) -> Quart:
    app = Quart(__name__)

    db = Database(config.database_url)
    hydra = HydraClient(config.hydra_admin_url)
    sse = RedisSseManager(config.redis_url)

    @app.before_serving
    async def startup():
        await db.connect()
        await db.migrate()
        await recover_stale_claims(db)
        logger.info("Database connected and migrated")

    @app.after_serving
    async def shutdown():
        await db.close()
        await hydra.close()

    # ------------------------------------------------------------------
    # Hydra login/consent endpoints
    # ------------------------------------------------------------------

    @app.get("/login")
    async def login():
        login_challenge = request.args.get("login_challenge")
        if not login_challenge:
            return jsonify({"error": "Missing login_challenge"}), 400
        # Fix 5: validate format before forwarding to Hydra admin API
        if not _HYDRA_CHALLENGE_RE.match(login_challenge):
            return jsonify({"error": "Invalid login_challenge"}), 400

        try:
            login_req = await hydra.get_login_request(login_challenge)
        except Exception as e:
            logger.error("Failed to fetch login request from Hydra: %s", e)
            return jsonify({"error": "Failed to fetch login request"}), 502

        # User already has a Hydra session - accept immediately without showing QR
        if login_req.get("skip"):
            subject = login_req["subject"]
            try:
                redirect_to = await hydra.accept_login(login_challenge, subject)
                if not _validate_redirect_to(redirect_to, config.hydra_public_url):
                    logger.error("Hydra returned suspicious redirect_to on skip-login: %.80s", redirect_to)
                    return jsonify({"error": "Internal error"}), 500
                return redirect(redirect_to)
            except Exception as e:
                logger.error("Failed to accept skipped login: %s", e)
                return jsonify({"error": "Internal error"}), 500

        try:
            await cleanup_expired_challenges(db)
            k1, lnurl_string, stream_token, session_id = await generate_k1_challenge(
                db, login_challenge, config
            )
            callback_url = f"{config.lnurl_callback_url}?tag=login&k1={k1}"
            qr_b64 = generate_qr_b64(lnurl_encode(callback_url))
        except Exception as e:
            logger.error("Failed to generate LNURL challenge: %s", e)
            return jsonify({"error": "Internal error"}), 500

        csp_nonce = base64.b64encode(os.urandom(16)).decode()
        response = await render_template(
            "login.html",
            lnurl=lnurl_string,
            qr_b64=qr_b64,
            session_id=session_id,
            csp_nonce=csp_nonce,
        )
        response = await make_response(response)
        # Cookie named per-session so multiple tabs don't overwrite each other.
        # session_id is a non-secret routing key; stream_token inside the cookie
        # is the actual secret.
        response.set_cookie(
            f"st_{session_id}",
            stream_token,
            httponly=True,
            samesite="Strict",
            secure=config.secure_cookies,
            max_age=config.auth_challenge_expiry_seconds,
            path="/lnurl/stream",
        )
        response.headers["Cache-Control"] = "no-store, private"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; "
            f"script-src 'nonce-{csp_nonce}'; "
            "style-src 'unsafe-inline'; "
            "img-src data:; "
            "connect-src 'self'; "
        )
        return response

    @app.get("/consent")
    async def consent():
        consent_challenge = request.args.get("consent_challenge")
        if not consent_challenge:
            return jsonify({"error": "Missing consent_challenge"}), 400
        # Fix 5: validate format
        if not _HYDRA_CHALLENGE_RE.match(consent_challenge):
            return jsonify({"error": "Invalid consent_challenge"}), 400

        try:
            consent_req = await hydra.get_consent_request(consent_challenge)
            requested = set(consent_req.get("requested_scope", []))
            disallowed = requested - config.consent_allowed_scopes
            if disallowed:
                logger.warning("Consent request contained disallowed scopes: %s", disallowed)
                return jsonify({"error": "Requested scopes are not permitted"}), 403
            subject = consent_req.get("subject", "")
            redirect_to = await hydra.accept_consent(
                consent_challenge, list(requested), subject
            )
            if not _validate_redirect_to(redirect_to, config.hydra_public_url):
                logger.error("Hydra returned suspicious redirect_to on consent: %.80s", redirect_to)
                return jsonify({"error": "Internal error"}), 500
            return redirect(redirect_to)
        except Exception as e:
            logger.error("Consent error: %s", e)
            return jsonify({"error": "Internal error"}), 500

    # ------------------------------------------------------------------
    # LNURL-auth endpoints
    # ------------------------------------------------------------------

    @app.get("/lnurl/callback")
    async def lnurl_callback():
        """Called by Lightning wallets after scanning the QR code."""
        tag = request.args.get("tag")
        k1 = request.args.get("k1")
        sig = request.args.get("sig")
        key = request.args.get("key")

        if tag != "login" or not all([k1, sig, key]):
            return jsonify({"status": "ERROR", "reason": "Invalid parameters"}), 400

        # Step 1 — atomic claim (pending → claimed).
        # Verifies sig inside the transaction while holding the row lock.
        # A bad sig or any failure rolls back; k1 stays pending so the wallet
        # can retry without a new QR scan. Returns claim_token for fencing.
        row = await claim_challenge(db, k1, sig, key)
        if row is None:
            return jsonify({"status": "ERROR", "reason": "Invalid or expired challenge"}), 400

        claim_token = row["claim_token"]

        # Step 2 — Hydra accept (outside the transaction).
        # On failure we unclaim (claimed → pending) so the wallet can retry.
        # claim_token ensures a stale unclaim from a slow/crashed pod is
        # discarded if the lease was already recovered and re-claimed.
        # Hydra's accept endpoint is idempotent: a second call for the same
        # challenge returns 200 with a fresh redirect_to, so replica retries
        # after a stale-claim recovery are safe.
        try:
            redirect_to = await hydra.accept_login(row["login_challenge"], subject=key)
        except Exception as e:
            logger.error("Failed to accept Hydra login for k1=%.16s...: %s", k1, e)
            await unclaim_challenge(db, k1, claim_token)
            return jsonify({"status": "ERROR", "reason": "Internal error"}), 500

        if not _validate_redirect_to(redirect_to, config.hydra_public_url):
            logger.error("Hydra returned suspicious redirect_to: %.80s", redirect_to)
            await unclaim_challenge(db, k1, claim_token)
            return jsonify({"status": "ERROR", "reason": "Internal error"}), 500

        # Step 3 — complete (claimed → completed), persisting redirect_to.
        # From this point the result is durable; Redis is best-effort only.
        # complete_challenge returns False when the claim_token no longer matches
        # (lease expired mid-flight, another replica re-claimed the row). Return
        # 500 so the wallet retries — Hydra's accept is idempotent so the retry
        # is safe. The retry loop will either find the row already completed (if
        # the other replica succeeded) or re-claim and complete it after that
        # replica's lease expires.
        completed = await complete_challenge(db, k1, pubkey=key, redirect_to=redirect_to, claim_token=claim_token)
        if not completed:
            logger.warning("complete_challenge missed claim for k1=%.16s... — lease expired mid-flight", k1)
            return jsonify({"status": "ERROR", "reason": "Internal error"}), 500

        # Step 4 — best-effort Redis publish for low-latency SSE delivery.
        # The SSE loop polls the DB periodically so Redis failure is not fatal.
        try:
            await sse.publish_auth(k1, redirect_to)
        except Exception as exc:
            logger.warning("Redis publish failed for k1=%.16s... (SSE will poll DB): %s", k1, exc)

        logger.info("Auth complete for pubkey=%.16s...", key)
        return jsonify({"status": "OK"}), 200

    @app.get("/lnurl/stream")
    async def stream_auth_status():
        """SSE stream the browser subscribes to while showing the QR code.

        Identified by st_<session_id> HttpOnly cookie. session_id is a
        non-secret routing key present in the page JS; stream_token inside
        the cookie is the secret. Per-session cookies prevent tab collisions.

        Delivery order: check DB first (handles Redis-failed callbacks and
        reconnects), then subscribe to Redis, then re-check DB once after
        subscribing to close the race between those two steps.
        """
        session_id = request.args.get("sid")
        if not session_id:
            return jsonify({"error": "Missing session id"}), 401

        stream_token = request.cookies.get(f"st_{session_id}")
        if not stream_token:
            return jsonify({"error": "Missing stream token"}), 401

        row = await db.fetchrow(
            "SELECT k1, expires_at, stream_token, redirect_to "
            "FROM auth_challenges WHERE session_id = $1",
            session_id,
        )
        if not row:
            return jsonify({"error": "Invalid session"}), 401
        if int(time.time()) > row["expires_at"]:
            return jsonify({"error": "Challenge expired"}), 410
        if not hmac.compare_digest(row["stream_token"] or "", stream_token):
            return jsonify({"error": "Invalid stream token"}), 401

        k1 = row["k1"]

        async def event_stream():
            yield ": " + "x" * 2048 + "\n\n"
            yield _sse_event("connected", {})

            # Fast path: callback already completed before SSE connected
            # (also covers Redis-failed callbacks — result is in the DB).
            if row["redirect_to"]:
                yield _sse_event("authenticated", {"redirect_to": row["redirect_to"]})
                return

            queue: asyncio.Queue = asyncio.Queue()

            async def _feed():
                try:
                    async for redirect_to in sse.listen_for_auth(
                        k1, timeout=float(config.auth_challenge_expiry_seconds)
                    ):
                        await queue.put(("auth", redirect_to))
                except Exception as exc:
                    logger.error("SSE listener error for k1=%.16s...: %s", k1, exc)
                finally:
                    await queue.put(("done", None))

            task = asyncio.create_task(_feed())
            try:
                # Re-check DB immediately after subscribing to close the race
                # between "DB had no result yet" and "callback wrote + published".
                recheck = await db.fetchrow(
                    "SELECT redirect_to FROM auth_challenges WHERE k1 = $1", k1
                )
                if recheck and recheck["redirect_to"]:
                    yield _sse_event("authenticated", {"redirect_to": recheck["redirect_to"]})
                    return

                while True:
                    try:
                        kind, value = await asyncio.wait_for(queue.get(), timeout=20)
                    except asyncio.TimeoutError:
                        # Heartbeat interval — also poll DB so Redis failure
                        # doesn't leave an already-completed auth invisible.
                        poll = await db.fetchrow(
                            "SELECT redirect_to FROM auth_challenges WHERE k1 = $1", k1
                        )
                        if poll and poll["redirect_to"]:
                            yield _sse_event("authenticated", {"redirect_to": poll["redirect_to"]})
                            return
                        yield ": heartbeat\n\n"
                        continue
                    if kind == "auth":
                        yield _sse_event("authenticated", {"redirect_to": value})
                        return
                    else:
                        # Redis listener timed out or closed. Do a final DB
                        # check before declaring expired — covers the race
                        # where complete_challenge() wrote redirect_to just
                        # before the Redis timeout fired.
                        final = await db.fetchrow(
                            "SELECT redirect_to FROM auth_challenges WHERE k1 = $1", k1
                        )
                        if final and final["redirect_to"]:
                            yield _sse_event("authenticated", {"redirect_to": final["redirect_to"]})
                        else:
                            yield _sse_event("expired", {"error": "Challenge expired"})
                        return
            finally:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

        return Response(
            event_stream(),
            content_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    @app.get("/health")
    async def health():
        return jsonify({"status": "ok"}), 200

    return app
