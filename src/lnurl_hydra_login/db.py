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

    async def migrate(self):
        await self.execute("""
            CREATE TABLE IF NOT EXISTS auth_challenges (
                k1 TEXT PRIMARY KEY,
                login_challenge TEXT NOT NULL,
                created_at BIGINT NOT NULL,
                expires_at BIGINT NOT NULL,
                used INTEGER DEFAULT 0 CHECK(used IN (0, 1))
            )
        """)
        await self.execute("""
            CREATE INDEX IF NOT EXISTS idx_auth_challenges_expires_at
            ON auth_challenges (expires_at)
        """)
