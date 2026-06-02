import contextlib

import asyncpg


class Database:
    def __init__(self, url: str):
        self._url = url
        self._pool: asyncpg.Pool | None = None

    async def connect(self):
        self._pool = await asyncpg.create_pool(self._url)

    async def close(self):
        if self._pool:
            await self._pool.close()

    async def execute(self, query: str, *args) -> str:
        async with self._pool.acquire() as conn:
            return await conn.execute(query, *args)

    async def fetchrow(self, query: str, *args):
        async with self._pool.acquire() as conn:
            return await conn.fetchrow(query, *args)

    async def fetchval(self, query: str, *args):
        async with self._pool.acquire() as conn:
            return await conn.fetchval(query, *args)

    @contextlib.asynccontextmanager
    async def transaction(self):
        """Yield a connection with an open transaction; commits on exit, rolls back on error."""
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                yield conn

    async def migrate(self):
        await self.execute("""
            CREATE TABLE IF NOT EXISTS auth_challenges (
                k1 TEXT PRIMARY KEY,
                login_challenge TEXT NOT NULL,
                created_at BIGINT NOT NULL,
                expires_at BIGINT NOT NULL,
                used INTEGER DEFAULT 0 CHECK(used IN (0, 1)),
                stream_token TEXT
            )
        """)
        # Add stream_token to existing deployments that predate this column
        await self.execute("""
            ALTER TABLE auth_challenges ADD COLUMN IF NOT EXISTS stream_token TEXT
        """)
        await self.execute("""
            CREATE INDEX IF NOT EXISTS idx_auth_challenges_expires_at
            ON auth_challenges (expires_at)
        """)
