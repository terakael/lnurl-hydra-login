import asyncio
import contextlib
import json
import logging
import time

from quart import Quart, Response, jsonify, redirect, render_template, request, send_file

from .auth import (
    cleanup_expired_challenges,
    generate_k1_challenge,
    lnurl_encode,
    mark_challenge_used,
    verify_lnurl_signature,
)
from .config import Config
from .db import Database
from .hydra import HydraClient
from .qr_utils import generate_qr_image
from .sse import RedisSseManager

logger = logging.getLogger(__name__)


def _sse_event(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def create_app(config: Config) -> Quart:
    app = Quart(__name__)

    db = Database(config.database_url)
    hydra = HydraClient(config.hydra_admin_url)
    sse = RedisSseManager(config.redis_url)

    @app.before_serving
    async def startup():
        await db.connect()
        await db.migrate()
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
                return redirect(redirect_to)
            except Exception as e:
                logger.error("Failed to accept skipped login: %s", e)
                return jsonify({"error": "Internal error"}), 500

        return await render_template("login.html", login_challenge=login_challenge)

    @app.get("/consent")
    async def consent():
        consent_challenge = request.args.get("consent_challenge")
        if not consent_challenge:
            return jsonify({"error": "Missing consent_challenge"}), 400

        try:
            consent_req = await hydra.get_consent_request(consent_challenge)
            grant_scope = consent_req.get("requested_scope", [])
            subject = consent_req.get("subject", "")
            redirect_to = await hydra.accept_consent(
                consent_challenge, grant_scope, subject
            )
            return redirect(redirect_to)
        except Exception as e:
            logger.error("Consent error: %s", e)
            return jsonify({"error": "Internal error"}), 500

    # ------------------------------------------------------------------
    # LNURL-auth endpoints
    # ------------------------------------------------------------------

    @app.get("/lnurl/generate")
    async def generate_lnurl():
        """Called by the login page JS to get a fresh k1 + LNURL."""
        login_challenge = request.args.get("login_challenge")
        if not login_challenge:
            return jsonify({"error": "Missing login_challenge"}), 400

        try:
            await cleanup_expired_challenges(db)
            k1, lnurl_string = await generate_k1_challenge(db, login_challenge, config)
            logger.info("Generated challenge k1=%.16s... for login_challenge=%.16s...", k1, login_challenge)
            return jsonify({"k1": k1, "lnurl": lnurl_string}), 200
        except Exception as e:
            logger.error("Failed to generate LNURL challenge: %s", e)
            return jsonify({"error": "Internal error"}), 500

    @app.get("/lnurl/qr/<k1>")
    async def get_qr_code(k1: str):
        """Serve the QR code image for a given k1 challenge."""
        try:
            row = await db.fetchrow(
                "SELECT expires_at FROM auth_challenges WHERE k1 = $1", k1
            )
            if not row or int(time.time()) > row["expires_at"]:
                return jsonify({"error": "Invalid or expired challenge"}), 404

            callback_url = f"{config.lnurl_callback_url}?tag=login&k1={k1}"
            lnurl_string = lnurl_encode(callback_url)
            img_io = await generate_qr_image(lnurl_string)
            return await send_file(img_io, mimetype="image/png")
        except Exception as e:
            logger.error("QR generation error: %s", e)
            return jsonify({"error": "Internal error"}), 500

    @app.get("/lnurl/callback")
    async def lnurl_callback():
        """Called by Lightning wallets after scanning the QR code."""
        tag = request.args.get("tag")
        k1 = request.args.get("k1")
        sig = request.args.get("sig")
        key = request.args.get("key")

        if tag != "login" or not all([k1, sig, key]):
            return jsonify({"status": "ERROR", "reason": "Invalid parameters"}), 400

        row = await db.fetchrow(
            "SELECT used, expires_at, login_challenge FROM auth_challenges WHERE k1 = $1",
            k1,
        )

        if not row:
            return jsonify({"status": "ERROR", "reason": "Invalid challenge"}), 400
        if row["used"]:
            return jsonify({"status": "ERROR", "reason": "Challenge already used"}), 400
        if int(time.time()) > row["expires_at"]:
            return jsonify({"status": "ERROR", "reason": "Challenge expired"}), 400

        if not await verify_lnurl_signature(k1, sig, key):
            return jsonify({"status": "ERROR", "reason": "Invalid signature"}), 400

        login_challenge = row["login_challenge"]
        await mark_challenge_used(db, k1)

        try:
            redirect_to = await hydra.accept_login(login_challenge, subject=key)
        except Exception as e:
            logger.error("Failed to accept Hydra login: %s", e)
            return jsonify({"status": "ERROR", "reason": "Internal error"}), 500

        await sse.publish_auth(k1, redirect_to)
        logger.info("Auth complete for pubkey=%.16s...", key)
        return jsonify({"status": "OK"}), 200

    @app.get("/lnurl/stream/<k1>")
    async def stream_auth_status(k1: str):
        """SSE stream the browser subscribes to while showing the QR code."""
        async def event_stream():
            # 2 KiB padding forces Cloudflare to flush its response buffer
            # before the first real event arrives at the browser.
            yield ": " + "x" * 2048 + "\n\n"
            yield _sse_event("connected", {"k1": k1})

            # Run the Redis listener in a background task so we can send
            # periodic heartbeat comments to keep Cloudflare from RST-ing
            # the HTTP/2 stream while the user is scanning the QR code.
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
                while True:
                    try:
                        kind, value = await asyncio.wait_for(queue.get(), timeout=20)
                    except asyncio.TimeoutError:
                        yield ": heartbeat\n\n"
                        continue
                    if kind == "auth":
                        yield _sse_event("authenticated", {"redirect_to": value})
                        return
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
