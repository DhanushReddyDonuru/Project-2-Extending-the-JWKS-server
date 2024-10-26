from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3

# Server configuration
hostName = "localhost"
serverPort = 8080

# Database path
DB_PATH = "totally_not_my_privateKeys.db"

# Connect to SQLite database and create table if it doesn't exist
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
''')
conn.commit()

def generate_and_store_key(expiration_hours):
    """Generate an RSA private key and store it in the database with expiration."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    exp_time = int((datetime.datetime.now() + datetime.timedelta(hours=expiration_hours)).timestamp())
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, exp_time))
    conn.commit()
    return cursor.lastrowid  # Return the kid after inserting the key

# Generate and store keys with unique kid
valid_kid = generate_and_store_key(expiration_hours=1)   # Valid key
expired_kid = generate_and_store_key(expiration_hours=-1)  # Expired key

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string."""
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

class MyServer(BaseHTTPRequestHandler):
    def do_POST(self):
        """Handle POST requests for JWT authentication."""
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            current_time = int(datetime.datetime.now().timestamp())
            expired = 'expired' in params

            if expired:
                cursor.execute("SELECT kid, key FROM keys WHERE exp <= ? LIMIT 1", (current_time,))
            else:
                cursor.execute("SELECT kid, key FROM keys WHERE exp > ? LIMIT 1", (current_time,))
            key_data = cursor.fetchone()

            if key_data:
                kid, private_key_pem = key_data
                private_key = serialization.load_pem_private_key(private_key_pem, password=None)

                token_payload = {
                    "user": "username",
                    "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1) if not expired else datetime.datetime.utcnow() - datetime.timedelta(hours=1)
                }
                headers = {
                    "kid": str(kid)  # Use the actual kid from the database
                }
                encoded_jwt = jwt.encode(token_payload, private_key, algorithm="RS256", headers=headers)

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(encoded_jwt, "utf-8"))
            else:
                self.send_response(404)
                self.end_headers()
            return

        self.send_response(405)
        self.end_headers()

    def do_GET(self):
        """Handle GET requests for JWKS."""
        if self.path == "/.well-known/jwks.json":
            current_time = int(datetime.datetime.now().timestamp())
            cursor.execute("SELECT kid, key FROM keys WHERE exp > ?", (current_time,))
            keys = cursor.fetchall()

            jwks = {"keys": []}
            for kid, key_pem in keys:
                private_key = serialization.load_pem_private_key(key_pem, password=None)
                public_key = private_key.public_key()
                public_numbers = public_key.public_numbers()

                jwks["keys"].append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(kid),  # Use the actual kid from the database
                    "n": int_to_base64(public_numbers.n),
                    "e": int_to_base64(public_numbers.e)
                })

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(jwks), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print("Server started http://%s:%s" % (hostName, serverPort))
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    conn.close()  # Close the database connection
    webServer.server_close()
