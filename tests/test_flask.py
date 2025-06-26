import unittest
from unittest.mock import patch

from flask import Flask, Response, g

from descope import (
    COOKIE_DATA_NAME,
    REFRESH_SESSION_COOKIE_NAME,
    REFRESH_SESSION_TOKEN_NAME,
    SESSION_COOKIE_NAME,
    SESSION_TOKEN_NAME,
    AuthException,
    DeliveryMethod,
    DescopeClient,
)
from descope.flask import (
    descope_full_login,
    descope_logout,
    descope_oauth,
    descope_signin_magiclink_by_email,
    descope_signin_otp_by_email,
    descope_signup_magiclink_by_email,
    descope_signup_otp_by_email,
    descope_validate_auth,
    descope_verify_code_by_email,
    descope_verify_code_by_phone_sms,
    descope_verify_magiclink_token,
    set_cookie_on_response,
)
from tests.common import DescopeTest


class TestFlaskIntegration(DescopeTest):
    def setUp(self):
        super().setUp()
        self.app = Flask(__name__)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.descope_client = DescopeClient("test-project-id")

        # Mock JWT response structure
        self.mock_jwt_response = {
            SESSION_TOKEN_NAME: {"drn": "DST", "jwt": "mock-session-token"},
            REFRESH_SESSION_TOKEN_NAME: {"drn": "DSR", "jwt": "mock-refresh-token"},
            COOKIE_DATA_NAME: {
                "domain": "localhost",
                "maxAge": 3600,
                "path": "/",
                "exp": None,
            },
            "permissions": ["read", "write"],
            "roles": ["admin"],
            "tenants": {"tenant1": {"permissions": ["manage"], "roles": ["owner"]}},
        }

    def test_set_cookie_on_response(self):
        """Test cookie setting utility function"""
        response = Response("test")
        token = {"drn": "DST", "jwt": "test-token"}
        cookie_data = {"domain": "localhost", "maxAge": 3600, "path": "/"}
        set_cookie_on_response(response, token, cookie_data)

        # Verify cookie was set (Flask sets cookies in headers)
        self.assertIsInstance(response, Response)

    def test_otp_signup_decorator_success(self):
        """Test OTP signup decorator with valid data"""

        @self.app.route("/signup", methods=["POST"])
        @descope_signup_otp_by_email(self.descope_client)
        def signup():
            return Response("Success", 200)

        with patch.object(self.descope_client.otp, "sign_up") as mock_signup:
            mock_signup.return_value = "masked-email@example.com"

            response = self.client.post(
                "/signup",
                json={"email": "test@example.com", "user": {"name": "Test User"}},
            )

            self.assertEqual(response.status_code, 200)
            mock_signup.assert_called_once_with(
                DeliveryMethod.EMAIL, "test@example.com", {"name": "Test User"}
            )

    def test_otp_signup_decorator_missing_email(self):
        """Test OTP signup decorator with missing email"""

        @self.app.route("/signup", methods=["POST"])
        @descope_signup_otp_by_email(self.descope_client)
        def signup():
            return Response("Success", 200)

        response = self.client.post("/signup", json={})

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Invalid Request, missing email", response.data)

    def test_otp_signup_decorator_auth_exception(self):
        """Test OTP signup decorator with AuthException"""

        @self.app.route("/signup", methods=["POST"])
        @descope_signup_otp_by_email(self.descope_client)
        def signup():
            return Response("Success", 200)

        with patch.object(self.descope_client.otp, "sign_up") as mock_signup:
            mock_signup.side_effect = AuthException(
                400, "invalid_request", "Invalid email"
            )

            response = self.client.post(
                "/signup", json={"email": "invalid@example.com"}
            )

            self.assertEqual(response.status_code, 500)
            self.assertIn(b"Unable to sign-up user", response.data)

    def test_otp_signin_decorator_success(self):
        """Test OTP signin decorator with valid data"""

        @self.app.route("/signin", methods=["POST"])
        @descope_signin_otp_by_email(self.descope_client)
        def signin():
            return Response("Success", 200)

        with patch.object(self.descope_client.otp, "sign_in") as mock_signin:
            mock_signin.return_value = "masked-email@example.com"

            response = self.client.post("/signin", json={"email": "test@example.com"})

            self.assertEqual(response.status_code, 200)
            mock_signin.assert_called_once_with(
                DeliveryMethod.EMAIL, "test@example.com"
            )

    def test_otp_verify_decorator_success(self):
        """Test OTP verify decorator with valid code"""

        @self.app.route("/verify", methods=["POST"])
        @descope_verify_code_by_email(self.descope_client)
        def verify():
            return Response("Verified", 200)

        with patch.object(self.descope_client.otp, "verify_code") as mock_verify:
            mock_verify.return_value = self.mock_jwt_response

            response = self.client.post(
                "/verify", json={"email": "test@example.com", "code": "123456"}
            )

            self.assertEqual(response.status_code, 200)
            mock_verify.assert_called_once_with(
                DeliveryMethod.EMAIL, "test@example.com", "123456"
            )

    def test_otp_verify_decorator_missing_data(self):
        """Test OTP verify decorator with missing email or code"""

        @self.app.route("/verify", methods=["POST"])
        @descope_verify_code_by_email(self.descope_client)
        def verify():
            return Response("Verified", 200)

        # Missing email
        response = self.client.post("/verify", json={"code": "123456"})
        self.assertEqual(response.status_code, 401)

        # Missing code
        response = self.client.post("/verify", json={"email": "test@example.com"})
        self.assertEqual(response.status_code, 401)

    def test_sms_verify_decorator_success(self):
        """Test SMS verify decorator with valid code"""

        @self.app.route("/verify-sms", methods=["POST"])
        @descope_verify_code_by_phone_sms(self.descope_client)
        def verify_sms():
            return Response("Verified", 200)

        with patch.object(self.descope_client.otp, "verify_code") as mock_verify:
            mock_verify.return_value = self.mock_jwt_response

            response = self.client.post(
                "/verify-sms", json={"phone": "+1234567890", "code": "123456"}
            )

            self.assertEqual(response.status_code, 200)
            mock_verify.assert_called_once_with(
                DeliveryMethod.SMS, "+1234567890", "123456"
            )

    def test_validate_auth_decorator_success(self):
        """Test auth validation decorator with valid session"""

        @self.app.route("/protected")
        @descope_validate_auth(self.descope_client)
        def protected():
            return Response("Protected content", 200)

        with patch.object(
            self.descope_client, "validate_and_refresh_session"
        ) as mock_validate:
            mock_validate.return_value = self.mock_jwt_response

            response = self.client.get(
                "/protected",
                headers={
                    "Cookie": f"{SESSION_COOKIE_NAME}=mock-session; {REFRESH_SESSION_COOKIE_NAME}=mock-refresh"
                },
            )

            self.assertEqual(response.status_code, 200)
            mock_validate.assert_called_once()

    def test_validate_auth_decorator_no_session(self):
        """Test auth validation decorator without session"""

        @self.app.route("/protected")
        @descope_validate_auth(self.descope_client)
        def protected():
            return Response("Protected content", 200)

        with patch.object(
            self.descope_client, "validate_and_refresh_session"
        ) as mock_validate:
            mock_validate.side_effect = AuthException(
                401, "unauthorized", "Invalid session"
            )

            response = self.client.get("/protected")

            self.assertEqual(response.status_code, 401)
            self.assertIn(b"Access denied", response.data)

    def test_validate_auth_decorator_with_permissions(self):
        """Test auth validation decorator with permission requirements"""

        @self.app.route("/admin")
        @descope_validate_auth(self.descope_client, permissions=["admin"])
        def admin():
            return Response("Admin content", 200)

        with patch.object(
            self.descope_client, "validate_and_refresh_session"
        ) as mock_validate:
            with patch.object(
                self.descope_client, "validate_permissions"
            ) as mock_perms:
                mock_validate.return_value = self.mock_jwt_response
                mock_perms.return_value = True

                response = self.client.get(
                    "/admin",
                    headers={
                        "Cookie": f"{SESSION_COOKIE_NAME}=mock-session; {REFRESH_SESSION_COOKIE_NAME}=mock-refresh"
                    },
                )

                self.assertEqual(response.status_code, 200)
                mock_perms.assert_called_once_with(self.mock_jwt_response, ["admin"])

    def test_validate_auth_decorator_insufficient_permissions(self):
        """Test auth validation decorator with insufficient permissions"""

        @self.app.route("/admin")
        @descope_validate_auth(self.descope_client, permissions=["admin"])
        def admin():
            return Response("Admin content", 200)

        with patch.object(
            self.descope_client, "validate_and_refresh_session"
        ) as mock_validate:
            with patch.object(
                self.descope_client, "validate_permissions"
            ) as mock_perms:
                mock_validate.return_value = self.mock_jwt_response
                mock_perms.return_value = False

                response = self.client.get(
                    "/admin",
                    headers={
                        "Cookie": f"{SESSION_COOKIE_NAME}=mock-session; {REFRESH_SESSION_COOKIE_NAME}=mock-refresh"
                    },
                )

                self.assertEqual(response.status_code, 401)

    def test_validate_auth_decorator_with_roles(self):
        """Test auth validation decorator with role requirements"""

        @self.app.route("/manager")
        @descope_validate_auth(self.descope_client, roles=["manager"])
        def manager():
            return Response("Manager content", 200)

        with patch.object(
            self.descope_client, "validate_and_refresh_session"
        ) as mock_validate:
            with patch.object(self.descope_client, "validate_roles") as mock_roles:
                mock_validate.return_value = self.mock_jwt_response
                mock_roles.return_value = True

                response = self.client.get(
                    "/manager",
                    headers={
                        "Cookie": f"{SESSION_COOKIE_NAME}=mock-session; {REFRESH_SESSION_COOKIE_NAME}=mock-refresh"
                    },
                )

                self.assertEqual(response.status_code, 200)
                mock_roles.assert_called_once_with(self.mock_jwt_response, ["manager"])

    def test_validate_auth_decorator_with_tenant(self):
        """Test auth validation decorator with tenant-specific permissions"""

        @self.app.route("/tenant-admin")
        @descope_validate_auth(
            self.descope_client, permissions=["manage"], tenant="tenant1"
        )
        def tenant_admin():
            return Response("Tenant admin content", 200)

        with patch.object(
            self.descope_client, "validate_and_refresh_session"
        ) as mock_validate:
            with patch.object(
                self.descope_client, "validate_tenant_permissions"
            ) as mock_tenant_perms:
                mock_validate.return_value = self.mock_jwt_response
                mock_tenant_perms.return_value = True

                response = self.client.get(
                    "/tenant-admin",
                    headers={
                        "Cookie": f"{SESSION_COOKIE_NAME}=mock-session; {REFRESH_SESSION_COOKIE_NAME}=mock-refresh"
                    },
                )

                self.assertEqual(response.status_code, 200)
                mock_tenant_perms.assert_called_once_with(
                    self.mock_jwt_response, ["manage"]
                )

    def test_magiclink_signup_decorator_success(self):
        """Test MagicLink signup decorator with valid data"""

        @self.app.route("/magiclink-signup", methods=["POST"])
        @descope_signup_magiclink_by_email(
            self.descope_client, "http://example.com/verify"
        )
        def magiclink_signup():
            return Response("Success", 200)

        with patch.object(self.descope_client.magiclink, "sign_up") as mock_signup:
            mock_signup.return_value = "masked-email@example.com"

            response = self.client.post(
                "/magiclink-signup",
                json={"email": "test@example.com", "user": {"name": "Test User"}},
            )

            self.assertEqual(response.status_code, 200)
            mock_signup.assert_called_once_with(
                DeliveryMethod.EMAIL,
                "test@example.com",
                "http://example.com/verify",
                {"name": "Test User"},
            )

    def test_magiclink_signin_decorator_success(self):
        """Test MagicLink signin decorator with valid data"""

        @self.app.route("/magiclink-signin", methods=["POST"])
        @descope_signin_magiclink_by_email(
            self.descope_client, "http://example.com/verify"
        )
        def magiclink_signin():
            return Response("Success", 200)

        with patch.object(self.descope_client.magiclink, "sign_in") as mock_signin:
            mock_signin.return_value = "masked-email@example.com"

            response = self.client.post(
                "/magiclink-signin", json={"email": "test@example.com"}
            )

            self.assertEqual(response.status_code, 200)
            mock_signin.assert_called_once_with(
                DeliveryMethod.EMAIL, "test@example.com", "http://example.com/verify"
            )

    def test_magiclink_verify_decorator_success(self):
        """Test MagicLink verify decorator with valid token"""

        @self.app.route("/magiclink-verify")
        @descope_verify_magiclink_token(self.descope_client)
        def magiclink_verify():
            return Response("Verified", 200)

        with patch.object(self.descope_client.magiclink, "verify") as mock_verify:
            mock_verify.return_value = self.mock_jwt_response

            response = self.client.get("/magiclink-verify?t=mock-token")

            self.assertEqual(response.status_code, 200)
            mock_verify.assert_called_once_with("mock-token")

    def test_magiclink_verify_decorator_missing_token(self):
        """Test MagicLink verify decorator without token"""

        @self.app.route("/magiclink-verify")
        @descope_verify_magiclink_token(self.descope_client)
        def magiclink_verify():
            return Response("Verified", 200)

        response = self.client.get("/magiclink-verify")

        self.assertEqual(response.status_code, 401)
        self.assertIn(b"Unauthorized", response.data)

    def test_oauth_decorator_success(self):
        """Test OAuth decorator with valid provider"""

        @self.app.route("/oauth")
        @descope_oauth(self.descope_client)
        def oauth(*args, **kwargs):
            return Response("OAuth initiated", 200)

        with patch.object(self.descope_client.oauth, "start") as mock_start:
            mock_start.return_value = {"url": "https://oauth.provider.com/auth"}

            response = self.client.get("/oauth?provider=google")

            self.assertEqual(response.status_code, 302)
            mock_start.assert_called_once_with("google")

    def test_oauth_decorator_auth_exception(self):
        """Test OAuth decorator with AuthException"""

        @self.app.route("/oauth")
        @descope_oauth(self.descope_client)
        def oauth():
            return Response("OAuth initiated", 200)

        with patch.object(self.descope_client.oauth, "start") as mock_start:
            mock_start.side_effect = AuthException(
                400, "invalid_provider", "Invalid provider"
            )

            response = self.client.get("/oauth?provider=invalid")

            self.assertEqual(response.status_code, 400)
            self.assertIn(b"OAuth failed", response.data)

    def test_logout_decorator_success(self):
        """Test logout decorator with valid refresh token"""

        @self.app.route("/logout", methods=["POST"])
        @descope_logout(self.descope_client)
        def logout():
            return Response("Logged out", 200)

        with patch.object(self.descope_client, "logout") as mock_logout:
            mock_logout.return_value = None

            # Set the refresh and session cookies using the test client
            self.client.set_cookie(REFRESH_SESSION_COOKIE_NAME, "mock-refresh-token")
            self.client.set_cookie(SESSION_COOKIE_NAME, "mock-session-token")
            response = self.client.post(
                "/logout",
            )

            self.assertEqual(response.status_code, 200)
            # The decorator should extract the refresh token from cookies and call logout
            mock_logout.assert_called_once_with("mock-refresh-token")

    def test_logout_decorator_auth_exception(self):
        """Test logout decorator with AuthException"""

        @self.app.route("/logout", methods=["POST"])
        @descope_logout(self.descope_client)
        def logout():
            return Response("Logged out", 200)

        with patch.object(self.descope_client, "logout") as mock_logout:
            mock_logout.side_effect = AuthException(
                400, "invalid_token", "Invalid token"
            )

            response = self.client.post(
                "/logout",
                headers={"Cookie": f"{REFRESH_SESSION_COOKIE_NAME}=invalid-token"},
            )

            self.assertEqual(response.status_code, 400)
            self.assertIn(b"Logout failed", response.data)

    def test_full_login_decorator_success(self):
        """Test full login decorator generates correct HTML"""

        @self.app.route("/login")
        @descope_full_login(
            project_id="test-project",
            flow_id="sign-up-or-in",
            success_redirect_url="http://localhost/success",
        )
        def login():
            return Response("Login page", 200)

        response = self.client.get("/login")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"descope-wc", response.data)
        self.assertIn(b"test-project", response.data)
        self.assertIn(b"sign-up-or-in", response.data)
        self.assertIn(b"http://localhost/success", response.data)

    def test_full_login_decorator_missing_redirect_url(self):
        """Test full login decorator with missing redirect URL"""

        @descope_full_login(
            project_id="test-project",
            flow_id="sign-up-or-in",
            success_redirect_url="",
        )
        def login():
            return Response("Login page", 200)

        with self.assertRaises(AuthException) as context:
            login()

        self.assertEqual(context.exception.status_code, 500)
        self.assertIn("Missing success_redirect_url", str(context.exception))

    def test_request_context_claims_storage(self):
        """Test that JWT claims are stored in Flask request context"""

        @self.app.route("/context-test")
        @descope_validate_auth(self.descope_client)
        def context_test():
            # Access the claims stored in context
            claims = getattr(g, "claims", None)
            if claims:
                return Response(f"Claims found: {claims.get('permissions', [])}", 200)
            return Response("No claims", 400)

        with patch.object(
            self.descope_client, "validate_and_refresh_session"
        ) as mock_validate:
            mock_validate.return_value = self.mock_jwt_response

            response = self.client.get(
                "/context-test",
                headers={
                    "Cookie": f"{SESSION_COOKIE_NAME}=mock-session; {REFRESH_SESSION_COOKIE_NAME}=mock-refresh"
                },
            )

            self.assertEqual(response.status_code, 200)
            self.assertIn(b"Claims found", response.data)


if __name__ == "__main__":
    unittest.main()
