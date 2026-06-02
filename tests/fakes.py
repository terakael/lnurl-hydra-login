from __future__ import annotations

import contextlib
import copy
import inspect


class FakeDatabase:
    def __init__(self):
        self.rows: dict[str, dict] = {}
        self.connected = False
        self.closed = False
        self.migrate_calls = 0

    async def connect(self):
        self.connected = True

    async def close(self):
        self.closed = True

    async def migrate(self):
        self.migrate_calls += 1

    def seed_challenge(
        self,
        *,
        k1: str,
        login_challenge: str = "login-challenge",
        created_at: int = 1_700_000_000,
        expires_at: int = 1_700_000_300,
        used: int = 0,
        stream_token: str = "stream-token",
        session_id: str = "session-id",
        redirect_to: str | None = None,
        authenticated_at: int | None = None,
        pubkey: str | None = None,
        claim_token: str | None = None,
        claim_expires_at: int | None = None,
    ) -> dict:
        row = {
            "k1": k1,
            "login_challenge": login_challenge,
            "created_at": created_at,
            "expires_at": expires_at,
            "used": used,
            "stream_token": stream_token,
            "session_id": session_id,
            "redirect_to": redirect_to,
            "authenticated_at": authenticated_at,
            "pubkey": pubkey,
            "claim_token": claim_token,
            "claim_expires_at": claim_expires_at,
        }
        self.rows[k1] = row
        return row

    async def execute(self, query: str, *args) -> str:
        compact = " ".join(query.split())
        if compact.startswith("INSERT INTO auth_challenges"):
            k1, login_challenge, created_at, expires_at, stream_token, session_id = args
            self.seed_challenge(
                k1=k1,
                login_challenge=login_challenge,
                created_at=created_at,
                expires_at=expires_at,
                stream_token=stream_token,
                session_id=session_id,
            )
            return "INSERT 0 1"

        if "DELETE FROM auth_challenges WHERE expires_at < $1" in compact:
            cutoff = args[0]
            deleted = [k1 for k1, row in self.rows.items() if row["expires_at"] < cutoff]
            for k1 in deleted:
                del self.rows[k1]
            return f"DELETE {len(deleted)}"

        if (
            "SET used = $1, claim_token = NULL, claim_expires_at = NULL WHERE used = $2 AND claim_expires_at < $3"
            in compact
        ):
            next_state, current_state, cutoff = args
            count = 0
            for row in self.rows.values():
                if row["used"] == current_state and row["claim_expires_at"] is not None and row["claim_expires_at"] < cutoff:
                    row["used"] = next_state
                    row["claim_token"] = None
                    row["claim_expires_at"] = None
                    count += 1
            return f"UPDATE {count}"

        if (
            "SET used = $2, claim_token = NULL, claim_expires_at = NULL WHERE k1 = $1 AND used = $3 AND claim_token = $4"
            in compact
        ):
            k1, next_state, current_state, claim_token = args
            row = self.rows.get(k1)
            count = 0
            if row and row["used"] == current_state and row["claim_token"] == claim_token:
                row["used"] = next_state
                row["claim_token"] = None
                row["claim_expires_at"] = None
                count = 1
            return f"UPDATE {count}"

        if "SET used = $2," in compact and "authenticated_at = $5," in compact:
            k1, next_state, pubkey, redirect_to, authenticated_at, current_state, claim_token = args
            row = self.rows.get(k1)
            count = 0
            if row and row["used"] == current_state and row["claim_token"] == claim_token:
                row["used"] = next_state
                row["pubkey"] = pubkey
                row["redirect_to"] = redirect_to
                row["authenticated_at"] = authenticated_at
                row["claim_token"] = None
                row["claim_expires_at"] = None
                count = 1
            return f"UPDATE {count}"

        if compact.startswith("CREATE TABLE") or compact.startswith("ALTER TABLE") or compact.startswith("CREATE INDEX"):
            return "OK"

        raise AssertionError(f"Unhandled fake execute query: {compact}")

    async def fetchrow(self, query: str, *args):
        compact = " ".join(query.split())
        if "FROM auth_challenges WHERE session_id = $1" in compact:
            session_id = args[0]
            for row in self.rows.values():
                if row["session_id"] == session_id:
                    return copy.deepcopy(row)
            return None

        if "SELECT redirect_to FROM auth_challenges WHERE k1 = $1" in compact:
            k1 = args[0]
            row = self.rows.get(k1)
            if row is None:
                return None
            return {"redirect_to": row["redirect_to"]}

        raise AssertionError(f"Unhandled fake fetchrow query: {compact}")

    async def fetchval(self, query: str, *args):
        raise AssertionError(f"Unhandled fake fetchval query: {query}")

    @contextlib.asynccontextmanager
    async def transaction(self):
        snapshot = copy.deepcopy(self.rows)
        conn = _FakeConnection(self)
        try:
            yield conn
        except Exception:
            self.rows = snapshot
            raise


class _FakeConnection:
    def __init__(self, db: FakeDatabase):
        self._db = db

    async def fetchrow(self, query: str, *args):
        compact = " ".join(query.split())
        if "FROM auth_challenges WHERE k1 = $1 FOR UPDATE" in compact:
            row = self._db.rows.get(args[0])
            return copy.deepcopy(row) if row else None
        raise AssertionError(f"Unhandled fake transaction fetchrow query: {compact}")

    async def execute(self, query: str, *args):
        compact = " ".join(query.split())
        if "SET used = $2, claim_token = $3, claim_expires_at = $4 WHERE k1 = $1" in compact:
            k1, next_state, claim_token, claim_expires_at = args
            row = self._db.rows.get(k1)
            if not row:
                return "UPDATE 0"
            row["used"] = next_state
            row["claim_token"] = claim_token
            row["claim_expires_at"] = claim_expires_at
            return "UPDATE 1"
        raise AssertionError(f"Unhandled fake transaction execute query: {compact}")


class FakeHydra:
    def __init__(self, public_url: str):
        self.public_url = public_url.rstrip("/")
        self.login_requests: dict[str, dict] = {}
        self.consent_requests: dict[str, dict] = {}
        self.login_accept_redirects: dict[str, str] = {}
        self.consent_accept_redirects: dict[str, str] = {}
        self.login_errors: dict[str, Exception] = {}
        self.consent_errors: dict[str, Exception] = {}
        self.accept_login_errors: dict[str, Exception] = {}
        self.accept_consent_errors: dict[str, Exception] = {}
        self.accept_login_calls: list[tuple[str, str]] = []
        self.accept_consent_calls: list[tuple[str, list[str], str]] = []
        self.on_accept_login = None
        self.on_accept_consent = None
        self.closed = False

    async def close(self):
        self.closed = True

    async def get_login_request(self, login_challenge: str) -> dict:
        if login_challenge in self.login_errors:
            raise self.login_errors[login_challenge]
        return copy.deepcopy(self.login_requests[login_challenge])

    async def accept_login(self, login_challenge: str, subject: str) -> str:
        self.accept_login_calls.append((login_challenge, subject))
        if login_challenge in self.accept_login_errors:
            raise self.accept_login_errors[login_challenge]
        if self.on_accept_login is not None:
            result = self.on_accept_login(login_challenge, subject)
            if inspect.isawaitable(result):
                result = await result
            if result is not None:
                return result
        return self.login_accept_redirects.get(
            login_challenge,
            f"{self.public_url}/oauth2/auth?login_verifier={login_challenge}",
        )

    async def get_consent_request(self, consent_challenge: str) -> dict:
        if consent_challenge in self.consent_errors:
            raise self.consent_errors[consent_challenge]
        return copy.deepcopy(self.consent_requests[consent_challenge])

    async def accept_consent(self, consent_challenge: str, grant_scope: list[str], subject: str) -> str:
        self.accept_consent_calls.append((consent_challenge, list(grant_scope), subject))
        if consent_challenge in self.accept_consent_errors:
            raise self.accept_consent_errors[consent_challenge]
        if self.on_accept_consent is not None:
            result = self.on_accept_consent(consent_challenge, grant_scope, subject)
            if inspect.isawaitable(result):
                result = await result
            if result is not None:
                return result
        return self.consent_accept_redirects.get(
            consent_challenge,
            f"{self.public_url}/oauth2/auth?consent_verifier={consent_challenge}",
        )


class FakeSseManager:
    def __init__(self):
        self.published: list[tuple[str, str]] = []
        self.publish_error: Exception | None = None
        self.listen_results: dict[str, list[str]] = {}
        self.listen_errors: dict[str, Exception] = {}
        self.listen_hooks: dict[str, object] = {}
        self.listen_calls: list[tuple[str, float]] = []

    async def publish_auth(self, k1: str, redirect_to: str) -> None:
        if self.publish_error is not None:
            raise self.publish_error
        self.published.append((k1, redirect_to))

    async def listen_for_auth(self, k1: str, timeout: float = 300.0):
        self.listen_calls.append((k1, timeout))

        hook = self.listen_hooks.get(k1)
        if hook is not None:
            result = hook()
            if inspect.isawaitable(result):
                await result

        if k1 in self.listen_errors:
            raise self.listen_errors[k1]

        for redirect_to in self.listen_results.get(k1, []):
            yield redirect_to
