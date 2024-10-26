import json
import requests
import unittest
import sqlite3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import jwt  # Import the jwt module

class TestMyServer(unittest.TestCase):
    BASE_URL = "http://localhost:8080"
    DB_PATH = "totally_not_my_privateKeys.db"

    def setUp(self):
        """Set up the test environment by ensuring the database has valid keys."""
        self.conn = sqlite3.connect(self.DB_PATH)
        self.cursor = self.conn.cursor()
        self.cursor.execute("DELETE FROM keys")  # Clear previous keys
        self.generate_test_keys()  # Generate valid and expired keys

    def tearDown(self):
        """Clean up the database after tests."""
        self.cursor.execute("DELETE FROM keys")
        self.conn.commit()
        self.conn.close()

    def generate_test_keys(self):
        """Generate and store a valid and an expired key in the database."""
        # Generate a valid key
        valid_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        valid_pem = valid_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        valid_expiry_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 3600  # 1 hour from now

        # Generate an expired key
        expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        expired_pem = expired_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        expired_expiry_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) - 1  # Expired

        # Store keys in the database
        self.cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (valid_pem, valid_expiry_time))
        self.cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (expired_pem, expired_expiry_time))
        self.conn.commit()

    def test_auth_valid_key(self):
        """Test authentication with a valid key."""
        response = requests.post(f"{self.BASE_URL}/auth")
        self.assertEqual(response.status_code, 200)
        token = response.text
        self.assertTrue(token.startswith("eyJ"))  # Check if the token is a JWT

        # Decode the JWT to verify its content
        decoded_token = jwt.decode(token, options={"verify_signature": False})
        self.assertEqual(decoded_token["user"], "username")

    def test_auth_expired_key(self):
        """Test authentication with an expired key."""
        response = requests.post(f"{self.BASE_URL}/auth?expired=true")
        self.assertEqual(response.status_code, 200)
        token = response.text
        self.assertTrue(token.startswith("eyJ"))  # Check if the token is a JWT

        # Decode the JWT to verify its content
        decoded_token = jwt.decode(token, options={"verify_signature": False})
        self.assertEqual(decoded_token["user"], "username")

    def test_auth_no_key(self):
        """Test authentication with no valid key (should return 404)."""
        # Remove all keys from the database to simulate no valid keys
        self.cursor.execute("DELETE FROM keys")
        self.conn.commit()
        response = requests.post(f"{self.BASE_URL}/auth?expired=false")
        self.assertEqual(response.status_code, 404)

    def test_jwks_response(self):
        """Test the JWKS response for valid keys."""
        response = requests.get(f"{self.BASE_URL}/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
        jwks = json.loads(response.text)
        self.assertIn('keys', jwks)
        self.assertGreater(len(jwks['keys']), 0)

    def test_jwks_no_keys(self):
        """Test JWKS response when there are no valid keys."""
        self.cursor.execute("DELETE FROM keys")  # Clear keys
        self.conn.commit()
        response = requests.get(f"{self.BASE_URL}/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
        jwks = json.loads(response.text)
        self.assertEqual(jwks, {"keys": []})  # Expect an empty keys array

if __name__ == '__main__':
    unittest.main()
