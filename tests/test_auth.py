import sqlite3
import tempfile
import unittest
from pathlib import Path

from app import create_app


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        database = Path(self.temp_dir.name) / "accounts.sqlite3"
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-only-secret",
                "DATABASE": str(database),
            }
        )
        self.client = self.app.test_client()
        self.csrf_token = self.client.get("/api/csrf").json["csrfToken"]

    def tearDown(self):
        self.temp_dir.cleanup()

    def post_json(self, path, data, csrf_token=None):
        return self.client.post(
            path,
            json=data,
            headers={"X-CSRF-Token": csrf_token or self.csrf_token},
        )

    def test_registration_hashes_password_and_creates_session(self):
        response = self.post_json(
            "/api/register",
            {
                "name": "Example User",
                "contactType": "email",
                "identifier": "USER@example.com",
                "password": "a-secure-password",
            },
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json["account"]["contact"], "user@example.com")
        self.assertTrue(self.client.get("/api/me").json["authenticated"])

        connection = sqlite3.connect(self.app.config["DATABASE"])
        try:
            password_hash = connection.execute(
                "SELECT password_hash FROM accounts"
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertNotEqual(password_hash, "a-secure-password")

    def test_duplicate_contact_is_rejected(self):
        data = {
            "name": "Example User",
            "contactType": "email",
            "identifier": "user@example.com",
            "password": "a-secure-password",
        }
        registration = self.post_json("/api/register", data)
        self.assertEqual(registration.status_code, 201)

        response = self.post_json(
            "/api/register", data, csrf_token=registration.json["csrfToken"]
        )

        self.assertEqual(response.status_code, 409)

    def test_phone_registration_and_login(self):
        self.assertEqual(
            self.post_json(
                "/api/register",
                {
                    "name": "Phone User",
                    "contactType": "phone",
                    "identifier": "+1 (202) 555-0198",
                    "password": "a-secure-password",
                },
            ).status_code,
            201,
        )
        logout_token = self.client.get("/api/csrf").json["csrfToken"]
        self.client.post("/api/logout", headers={"X-CSRF-Token": logout_token})
        token = self.client.get("/api/csrf").json["csrfToken"]

        response = self.post_json(
            "/api/login",
            {
                "contactType": "phone",
                "identifier": "+12025550198",
                "password": "a-secure-password",
            },
            csrf_token=token,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["account"]["contactType"], "phone")

    def test_login_rejects_wrong_password_and_requires_csrf(self):
        self.post_json(
            "/api/register",
            {
                "name": "Example User",
                "contactType": "email",
                "identifier": "user@example.com",
                "password": "a-secure-password",
            },
        )
        logout_token = self.client.get("/api/csrf").json["csrfToken"]
        self.client.post("/api/logout", headers={"X-CSRF-Token": logout_token})

        missing_csrf = self.client.post(
            "/api/login",
            json={
                "contactType": "email",
                "identifier": "user@example.com",
                "password": "a-secure-password",
            },
        )
        refreshed_token = self.client.get("/api/csrf").json["csrfToken"]
        wrong_password = self.post_json(
            "/api/login",
            {
                "contactType": "email",
                "identifier": "user@example.com",
                "password": "incorrect-password",
            },
            csrf_token=refreshed_token,
        )

        self.assertEqual(missing_csrf.status_code, 400)
        self.assertEqual(wrong_password.status_code, 401)


if __name__ == "__main__":
    unittest.main()
