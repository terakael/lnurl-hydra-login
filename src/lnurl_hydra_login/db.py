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
                used INTEGER DEFAULT 0 CHECK(used IN (0, 1, 2)),
                stream_token TEXT,
                session_id TEXT,
                redirect_to TEXT,
                authenticated_at BIGINT,
                pubkey TEXT
            )
        """)
        # Widen the used constraint from (0,1) to (0,1,2) for the tri-state
        # machine. Postgres requires drop + add to change a check constraint.
        await self.execute("""
            ALTER TABLE auth_challenges
            DROP CONSTRAINT IF EXISTS auth_challenges_used_check
        """)
        await self.execute("""
            ALTER TABLE auth_challenges
            ADD CONSTRAINT auth_challenges_used_check
            CHECK (used IN (0, 1, 2))
        """)
        for col, typedef in [
            ("stream_token",    "TEXT"),
            ("session_id",      "TEXT"),
            ("redirect_to",     "TEXT"),
            ("authenticated_at","BIGINT"),
            ("pubkey",          "TEXT"),
        ]:
            await self.execute(
                f"ALTER TABLE auth_challenges ADD COLUMN IF NOT EXISTS {col} {typedef}"
            )
        await self.execute("""
            CREATE INDEX IF NOT EXISTS idx_auth_challenges_expires_at
            ON auth_challenges (expires_at)
        """)
        await self.execute("""
            CREATE INDEX IF NOT EXISTS idx_auth_challenges_stream_token
            ON auth_challenges (stream_token)
        """)
        await self.execute("""
            CREATE INDEX IF NOT EXISTS idx_auth_challenges_session_id
            ON auth_challenges (session_id)
        """)
