"""
Test suite for the JWKS server (Project 2).
Run with:  pytest --cov=server --cov-report=term-missing
"""

import time
import json
import pytest
from io import BytesIO
import server as srv


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    """Point DB_FILE at a temp file for every test so tests don't share state."""
    monkeypatch.setattr(srv, "DB_FILE", str(tmp_path / "test.db"))
    srv.init_db()


@pytest.fixture()
def seeded():
    """Seed one valid + one expired key."""
    srv.seed_keys()


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

class TestInitDb:
    def test_creates_keys_table(self):
        with srv.get_db() as conn:
            result = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='keys'"
            ).fetchone()
        assert result is not None

    def test_is_idempotent(self):
        srv.init_db()
        srv.init_db()


class TestSaveKey:
    def test_inserts_row(self):
        pem = srv.generate_pem()
        srv.save_key(pem, int(time.time()) + 3600)
        with srv.get_db() as conn:
            count = conn.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
        assert count == 1

    def test_kid_autoincrements(self):
        pem = srv.generate_pem()
        srv.save_key(pem, int(time.time()) + 3600)
        srv.save_key(pem, int(time.time()) + 7200)
        with srv.get_db() as conn:
            kids = [r[0] for r in conn.execute("SELECT kid FROM keys").fetchall()]
        assert kids == [1, 2]


class TestGetValidKey:
    def test_returns_none_when_empty(self):
        assert srv.get_valid_key() is None

    def test_returns_valid_key(self):
        pem = srv.generate_pem()
        srv.save_key(pem, int(time.time()) + 3600)
        row = srv.get_valid_key()
        assert row is not None
        assert row[1] == pem

    def test_skips_expired_keys(self):
        srv.save_key(srv.generate_pem(), int(time.time()) - 1)
        assert srv.get_valid_key() is None


class TestGetExpiredKey:
    def test_returns_none_when_empty(self):
        assert srv.get_expired_key() is None

    def test_returns_expired_key(self):
        srv.save_key(srv.generate_pem(), int(time.time()) - 1)
        assert srv.get_expired_key() is not None

    def test_skips_valid_keys(self):
        srv.save_key(srv.generate_pem(), int(time.time()) + 3600)
        assert srv.get_expired_key() is None


class TestGetAllValidKeys:
    def test_empty_db(self):
        assert srv.get_all_valid_keys() == []

    def test_only_returns_valid(self):
        srv.save_key(srv.generate_pem(), int(time.time()) + 3600)
        srv.save_key(srv.generate_pem(), int(time.time()) - 1)
        rows = srv.get_all_valid_keys()
        assert len(rows) == 1


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

class TestGeneratePem:
    def test_is_pem_bytes(self):
        pem = srv.generate_pem()
        assert pem.startswith(b"-----BEGIN RSA PRIVATE KEY-----")

    def test_generates_unique_keys(self):
        assert srv.generate_pem() != srv.generate_pem()


class TestSeedKeys:
    def test_inserts_two_keys(self):
        srv.seed_keys()
        with srv.get_db() as conn:
            count = conn.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
        assert count == 2

    def test_one_valid_one_expired(self):
        srv.seed_keys()
        assert srv.get_valid_key() is not None
        assert srv.get_expired_key() is not None


# ---------------------------------------------------------------------------
# JWKS / JWT helpers
# ---------------------------------------------------------------------------

class TestIntToBase64:
    def test_known_exponent(self):
        assert srv.int_to_base64(65537) == "AQAB"

    def test_no_padding_characters(self):
        assert "=" not in srv.int_to_base64(255)

    def test_odd_length_hex(self):
        result = srv.int_to_base64(1)
        assert isinstance(result, str)


class TestBuildJwk:
    def test_contains_required_fields(self):
        pem = srv.generate_pem()
        jwk = srv.build_jwk(1, pem)
        for field in ("alg", "kty", "use", "kid", "n", "e"):
            assert field in jwk

    def test_kty_is_rsa(self):
        pem = srv.generate_pem()
        assert srv.build_jwk(1, pem)["kty"] == "RSA"

    def test_kid_is_string(self):
        pem = srv.generate_pem()
        assert srv.build_jwk(42, pem)["kid"] == "42"


class TestBuildJwks:
    def test_empty_rows(self):
        assert srv.build_jwks([]) == {"keys": []}

    def test_single_key(self):
        pem = srv.generate_pem()
        srv.save_key(pem, int(time.time()) + 3600)
        rows = srv.get_all_valid_keys()
        jwks = srv.build_jwks(rows)
        assert len(jwks["keys"]) == 1

    def test_multiple_keys(self):
        srv.save_key(srv.generate_pem(), int(time.time()) + 3600)
        srv.save_key(srv.generate_pem(), int(time.time()) + 7200)
        rows = srv.get_all_valid_keys()
        assert len(srv.build_jwks(rows)["keys"]) == 2


class TestBuildJwt:
    def test_returns_string(self):
        pem = srv.generate_pem()
        token = srv.build_jwt(1, pem)
        assert isinstance(token, str)

    def test_is_valid_jwt_format(self):
        pem = srv.generate_pem()
        token = srv.build_jwt(1, pem)
        assert token.count(".") == 2

    def test_expired_jwt_format(self):
        pem = srv.generate_pem()
        token = srv.build_jwt(1, pem, expired=True)
        assert token.count(".") == 2


# ---------------------------------------------------------------------------
# HTTP handler tests
# ---------------------------------------------------------------------------

def make_handler(method: str, path: str):
    """Create a MyServer instance without a real socket."""
    handler = srv.MyServer.__new__(srv.MyServer)
    handler.path = path
    handler.wfile = BytesIO()
    handler.rfile = BytesIO()
    handler.headers = {}
    handler.client_address = ("127.0.0.1", 0)
    handler.server = None
    handler.requestline = f"{method} {path} HTTP/1.1"
    handler.request_version = "HTTP/1.1"
    handler.command = method
    return handler


def get_status(handler) -> str:
    handler.wfile.seek(0)
    return handler.wfile.read().decode().split(" ")[1] if handler.wfile.tell() > 0 else ""


def get_raw_body(handler) -> str:
    handler.wfile.seek(0)
    raw = handler.wfile.read().decode()
    parts = raw.split("\r\n\r\n", 1)
    return parts[1].strip() if len(parts) > 1 else ""


class TestGetHandler:
    def test_jwks_returns_200(self):
        h = make_handler("GET", "/.well-known/jwks.json")
        h.do_GET()
        h.wfile.seek(0)
        assert b"200" in h.wfile.read()

    def test_jwks_empty(self):
        h = make_handler("GET", "/.well-known/jwks.json")
        h.do_GET()
        assert get_raw_body(h) == '{"keys": []}'

    def test_jwks_with_valid_key(self, seeded):
        h = make_handler("GET", "/.well-known/jwks.json")
        h.do_GET()
        data = json.loads(get_raw_body(h))
        assert len(data["keys"]) == 1

    def test_unknown_path_405(self):
        h = make_handler("GET", "/unknown")
        h.do_GET()
        h.wfile.seek(0)
        assert b"405" in h.wfile.read()


class TestPostHandler:
    def test_auth_returns_jwt(self, seeded):
        h = make_handler("POST", "/auth")
        h.do_POST()
        body = get_raw_body(h)
        assert body.count(".") == 2

    def test_auth_expired_returns_jwt(self, seeded):
        h = make_handler("POST", "/auth?expired=true")
        h.do_POST()
        body = get_raw_body(h)
        assert body.count(".") == 2

    def test_auth_no_valid_key_500(self):
        srv.save_key(srv.generate_pem(), int(time.time()) - 1)
        h = make_handler("POST", "/auth")
        h.do_POST()
        h.wfile.seek(0)
        assert b"500" in h.wfile.read()

    def test_auth_no_expired_key_500(self):
        srv.save_key(srv.generate_pem(), int(time.time()) + 3600)
        h = make_handler("POST", "/auth?expired=true")
        h.do_POST()
        h.wfile.seek(0)
        assert b"500" in h.wfile.read()

    def test_unknown_path_405(self):
        h = make_handler("POST", "/unknown")
        h.do_POST()
        h.wfile.seek(0)
        assert b"405" in h.wfile.read()


class TestOtherMethods:
    def test_put_405(self):
        h = make_handler("PUT", "/auth")
        h.do_PUT()
        h.wfile.seek(0)
        assert b"405" in h.wfile.read()

    def test_patch_405(self):
        h = make_handler("PATCH", "/auth")
        h.do_PATCH()
        h.wfile.seek(0)
        assert b"405" in h.wfile.read()

    def test_delete_405(self):
        h = make_handler("DELETE", "/auth")
        h.do_DELETE()
        h.wfile.seek(0)
        assert b"405" in h.wfile.read()

    def test_head_405(self):
        h = make_handler("HEAD", "/auth")
        h.do_HEAD()
        h.wfile.seek(0)
        assert b"405" in h.wfile.read()
