import asyncio
import json
import logging
from typing import AsyncGenerator

import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

_CHANNEL_PREFIX = "lnurl:auth:"
_RESULT_PREFIX = "lnurl:result:"
_RESULT_TTL = 60  # seconds to hold result for late SSE subscribers


class RedisSseManager:
    def __init__(self, redis_url: str):
        self._redis: aioredis.Redis = aioredis.from_url(
            redis_url, decode_responses=True
        )

    async def publish_auth(self, k1: str, redirect_to: str) -> None:
        """Called by the wallet callback handler after successful auth.

        Stores the result briefly so late SSE subscribers can still receive it,
        then publishes to the channel for any currently-waiting subscribers.
        """
        payload = json.dumps({"redirect_to": redirect_to})
        await self._redis.setex(f"{_RESULT_PREFIX}{k1}", _RESULT_TTL, payload)
        await self._redis.publish(f"{_CHANNEL_PREFIX}{k1}", payload)
        logger.info("Published auth notification for k1=%.16s...", k1)

    async def listen_for_auth(
        self, k1: str, timeout: float = 300.0
    ) -> AsyncGenerator[str, None]:
        """Async generator yielding redirect_to once when auth completes.

        Checks for a cached result first (handles the race where the wallet
        calls back before the browser opens the SSE connection), then falls
        back to a Redis pub/sub subscription.
        """
        # Fast path: auth already completed before SSE connected
        cached = await self._redis.get(f"{_RESULT_PREFIX}{k1}")
        if cached:
            logger.info("Returning cached auth result for k1=%.16s...", k1)
            yield json.loads(cached)["redirect_to"]
            return

        pubsub = self._redis.pubsub()
        await pubsub.subscribe(f"{_CHANNEL_PREFIX}{k1}")
        logger.info("Subscribed to Redis channel for k1=%.16s...", k1)
        try:
            async with asyncio.timeout(timeout):
                async for message in pubsub.listen():
                    if message["type"] == "message":
                        data = json.loads(message["data"])
                        logger.info(
                            "Auth notification received for k1=%.16s...", k1
                        )
                        yield data["redirect_to"]
                        return
        except TimeoutError:
            logger.info("SSE timeout for k1=%.16s...", k1)
        finally:
            await pubsub.aclose()
