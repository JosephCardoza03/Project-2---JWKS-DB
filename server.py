#Project

# Standard library HTTP server classes
from http.server import BaseHTTPRequestHandler, HTTPServer

# Cryptography library for RSA key generation and serialization
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# URL parsing utilities for extracting path and query parameters
from urllib.parse import urlparse, parse_qs

# base64 for encoding RSA key components into JWKS format
import base64

# json for serializing Python dicts into HTTP response bodies
import json

# PyJWT for signing and encoding JSON Web Tokens
import jwt

# datetime for computing token expiry timestamps
import datetime

# sqlite3 for interacting with the local SQLite database
import sqlite3

# time 
import time



# The hostname the HTTP server will bind to
HOST = "localhost"

# The port the HTTP server will listen on
PORT = 8080

# The SQLite database filename (required name per project spec)
DB_FILE = "totally_not_my_privateKeys.db"

def get_db() -> sqlite3.Connection:
    """
    Open and return a connection to the SQLite database file.
    """
    # sqlite3.connect opens the file if it exists, or creates it if it doesn't
    return sqlite3.connect(DB_FILE)


def init_db() -> None:
 
    with get_db() as conn:
        # CREATE TABLE IF NOT EXISTS ensures this is safe to call multiple times
        # without raising an error or overwriting existing data
        conn.execute("""
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
        """)
        # Commit the transaction so the table creation is persisted to disk
        conn.commit()


def save_key(pem_bytes: bytes, exp: int) -> None:
 
    with get_db() as conn:
        # Parameterized INSERT — the (?) placeholders are filled by sqlite3
        # with the tuple values, so user data never touches the query string
        conn.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (pem_bytes, exp)  # pem_bytes stored as BLOB, exp as INTEGER
        )
        # Commit so the new row is immediately visible to other queries
        conn.commit()


def get_valid_key() -> tuple | None:

    # Get the current time as a Unix timestamp for comparison with exp column
    now = int(time.time())
    with get_db() as conn:
        # Parameterized SELECT — 'now' is a bound parameter, never interpolated
        # exp > now means the key has not yet expired
        # LIMIT 1 means we only need one valid key to sign with
        row = conn.execute(
            "SELECT kid, key FROM keys WHERE exp > ? LIMIT 1",
            (now,)
        ).fetchone()  # returns a tuple or None if no rows matched
    return row


def get_expired_key() -> tuple | None:
  
    # Get the current time as a Unix timestamp for comparison with exp column
    now = int(time.time())
    with get_db() as conn:
        # Parameterized SELECT — 'now' is a bound parameter, never interpolated
        # exp <= now means the key's expiry time is in the past
        # LIMIT 1 means we only need one expired key
        row = conn.execute(
            "SELECT kid, key FROM keys WHERE exp <= ? LIMIT 1",
            (now,)
        ).fetchone()  # returns a tuple or None if no rows matched
    return row


def get_all_valid_keys() -> list:
 
    # Get the current time as a Unix timestamp for comparison with exp column
    now = int(time.time())
    with get_db() as conn:
        # Parameterized SELECT — 'now' is a bound parameter, never interpolated
        # Returns all rows where the key has not yet expired
        rows = conn.execute(
            "SELECT kid, key FROM keys WHERE exp > ?",
            (now,)
        ).fetchall()  # returns a list of tuples (empty list if no rows matched)
    return rows


# Key generation

def generate_pem() -> bytes:

    # Generate an RSA private key 
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Serialize the key to PKCS1 PEM format 

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )


def seed_keys() -> None:
    # Capture the current Unix timestamp once so both keys share the same reference point
    now = int(time.time())

    # Insert a valid key that expires 3600 seconds (1 hour) from now
    save_key(generate_pem(), now + 3600)

    # Insert an expired key whose expiry was 1 second ago
    save_key(generate_pem(), now - 1)

#JWKS SETUP
def int_to_base64(value: int) -> str:

    # Convert the integer to a hex string 
    value_hex = format(value, 'x')

    # If odd, pad with a leading zero
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex

    # Convert the hex string to raw bytes
    value_bytes = bytes.fromhex(value_hex)

    # Base64URL-encode the bytes 
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')

    # Return as a plain string (not bytes)
    return encoded.decode('utf-8')


def build_jwk(kid: int, pem_bytes: bytes) -> dict:

    # Deserialize the PEM bytes back into a private key object
    private_key = serialization.load_pem_private_key(pem_bytes, password=None)

    # Extract the numeric components (p, q, n, e, d, etc.) from the private key
    numbers = private_key.private_numbers()

    # Build and return the JWK dict using the public key components 
    # We only expose the public numbers — never the private components
    return {
        "alg": "RS256",                                     # signing algorithm
        "kty": "RSA",                                       # key type
        "use": "sig",                                       # intended use: signature verification
        "kid": str(kid),                                    # key ID from the database
        "n": int_to_base64(numbers.public_numbers.n),      # RSA modulus (Base64URL encoded)
        "e": int_to_base64(numbers.public_numbers.e),      # RSA public exponent (Base64URL encoded)
    }


def build_jwks(rows: list) -> dict:

    # Build a JWK for each row and wrap them in the standard JWKS envelope
    return {"keys": [build_jwk(kid, pem_bytes) for kid, pem_bytes in rows]}


def build_jwt(kid: int, pem_bytes: bytes, expired: bool = False) -> str:

    # Use the current UTC time as the base for computing expiry
    now = datetime.datetime.utcnow()

    # If expired=True, backdate the expiry by 1 hour so the token is already invalid
    # Otherwise, set the expiry 1 hour in the future (a normal valid token)
    exp = now - datetime.timedelta(hours=1) if expired else now + datetime.timedelta(hours=1)

    # Build the JWT payload with the username and computed expiry
    payload = {"user": "username", "exp": exp}

    # Embed the key ID in the JWT header so verifiers know which public key to use
    headers = {"kid": str(kid)}

    # Sign the JWT with the private key
    return jwt.encode(payload, pem_bytes, algorithm="RS256", headers=headers)


# HTTP handler

class MyServer(BaseHTTPRequestHandler):
    """HTTP request handler for the JWKS server."""

    def do_PUT(self):
        """Reject PUT — not supported by this server."""
        self.send_response(405)  # 405 Method Not Allowed
        self.end_headers()

    def do_PATCH(self):
        """Reject PATCH — not supported by this server."""
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        """Reject DELETE — not supported by this server."""
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        """Reject HEAD — not supported by this server."""
        self.send_response(405)
        self.end_headers()

    def do_POST(self):

        # Parse the request path to separate the route from any query parameters
        parsed_path = urlparse(self.path)

        # Extract query parameters into a dict (e.g. ?expired=true → {'expired': ['true']})
        params = parse_qs(parsed_path.query)

        # Only /auth is supported — return 405 for anything else
        if parsed_path.path != "/auth":
            self.send_response(405)
            self.end_headers()
            return

        # Check if the ?expired query parameter is present in the request
        use_expired = "expired" in params

        # Fetch the appropriate key from the database based on the expired flag
        row = get_expired_key() if use_expired else get_valid_key()

        # If no suitable key exists in the database, return a 500 error
        if row is None:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b'{"error": "no suitable key found"}')
            return

        # Unpack the database row into the key ID and PEM bytes
        kid, pem_bytes = row

        # Sign a JWT with the selected key and write it to the response
        token = build_jwt(kid, pem_bytes, expired=use_expired)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(bytes(token, "utf-8"))

    def do_GET(self):
  
        # Only /.well-known/jwks.json is supported — return 405 for anything else
        if self.path != "/.well-known/jwks.json":
            self.send_response(405)
            self.end_headers()
            return

        # Fetch all currently valid (non-expired) keys from the database
        rows = get_all_valid_keys()

        # Serialize the JWKS dict to JSON bytes for the response body
        body = bytes(json.dumps(build_jwks(rows)), "utf-8")

        # Send the response with the appropriate Content-Type header
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    # Set up the database and seed initial keys before accepting any requests
    init_db()
    seed_keys()

    # Create and start the HTTP server on the configured host and port
    webServer = HTTPServer((HOST, PORT), MyServer)
    print(f"JWKS server running at http://{HOST}:{PORT}")

    try:
        # Block and serve requests indefinitely until interrupted
        webServer.serve_forever()
    except KeyboardInterrupt:
        # Gracefully handle Ctrl+C shutdown
        pass

    # Clean up the server socket on exit
    webServer.server_close()