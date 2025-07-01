"""
Test the monkey-patch async approach.

This tests the dynamic async method addition without maintaining
separate async classes. Comprehensive testing of all auth methods
and client-level async functionality.
"""

import unittest
from unittest.mock import patch
from descope.descope_client_async import AsyncDescopeClient
from descope import DeliveryMethod
from descope.exceptions import AuthException


class TestMonkeyPatchAsync(unittest.IsolatedAsyncioTestCase):
    """Test monkey-patch async functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.project_id = "test_project_id"

    def test_async_client_creation(self):
        """Test that monkey-patched async client can be created."""
        client = AsyncDescopeClient(project_id=self.project_id)

        # Verify client properties
        self.assertEqual(client._auth.project_id, self.project_id)
        self.assertIsNotNone(client.otp)

        # Verify async methods were added to all auth methods
        self.assertTrue(hasattr(client.otp, "sign_up_async"))
        self.assertTrue(hasattr(client.otp, "sign_in_async"))
        self.assertTrue(hasattr(client.otp, "verify_code_async"))
        self.assertTrue(hasattr(client.otp, "sign_up_or_in_async"))
        self.assertTrue(hasattr(client.otp, "update_user_email_async"))
        self.assertTrue(hasattr(client.otp, "update_user_phone_async"))

        # Verify MagicLink async methods
        self.assertTrue(hasattr(client.magiclink, "sign_up_async"))
        self.assertTrue(hasattr(client.magiclink, "sign_in_async"))
        self.assertTrue(hasattr(client.magiclink, "verify_async"))
        self.assertTrue(hasattr(client.magiclink, "sign_up_or_in_async"))
        self.assertTrue(hasattr(client.magiclink, "update_user_email_async"))
        self.assertTrue(hasattr(client.magiclink, "update_user_phone_async"))

        # Verify EnchantedLink async methods
        self.assertTrue(hasattr(client.enchantedlink, "sign_up_async"))
        self.assertTrue(hasattr(client.enchantedlink, "sign_in_async"))
        self.assertTrue(hasattr(client.enchantedlink, "verify_async"))
        self.assertTrue(hasattr(client.enchantedlink, "get_session_async"))
        self.assertTrue(hasattr(client.enchantedlink, "sign_up_or_in_async"))
        self.assertTrue(hasattr(client.enchantedlink, "update_user_email_async"))

        # Verify OAuth async methods
        self.assertTrue(hasattr(client.oauth, "start_async"))
        self.assertTrue(hasattr(client.oauth, "exchange_token_async"))

        # Verify SSO async methods
        self.assertTrue(hasattr(client.sso, "start_async"))
        self.assertTrue(hasattr(client.sso, "exchange_token_async"))

        # Verify SAML async methods (deprecated but still tested)
        self.assertTrue(hasattr(client.saml, "start_async"))
        self.assertTrue(hasattr(client.saml, "exchange_token_async"))

        # Verify TOTP async methods
        self.assertTrue(hasattr(client.totp, "sign_up_async"))
        self.assertTrue(hasattr(client.totp, "sign_in_code_async"))
        self.assertTrue(hasattr(client.totp, "update_user_async"))

        # Verify WebAuthn async methods
        self.assertTrue(hasattr(client.webauthn, "sign_up_start_async"))
        self.assertTrue(hasattr(client.webauthn, "sign_up_finish_async"))
        self.assertTrue(hasattr(client.webauthn, "sign_in_start_async"))
        self.assertTrue(hasattr(client.webauthn, "sign_in_finish_async"))
        self.assertTrue(hasattr(client.webauthn, "sign_up_or_in_start_async"))
        self.assertTrue(hasattr(client.webauthn, "update_start_async"))
        self.assertTrue(hasattr(client.webauthn, "update_finish_async"))

        # Verify Password async methods
        self.assertTrue(hasattr(client.password, "sign_up_async"))
        self.assertTrue(hasattr(client.password, "sign_in_async"))
        self.assertTrue(hasattr(client.password, "send_reset_async"))
        self.assertTrue(hasattr(client.password, "update_async"))
        self.assertTrue(hasattr(client.password, "replace_async"))
        self.assertTrue(hasattr(client.password, "get_policy_async"))

        # Verify original methods still exist
        self.assertTrue(hasattr(client.otp, "sign_up"))
        self.assertTrue(hasattr(client.otp, "sign_in"))
        self.assertTrue(hasattr(client.otp, "verify_code"))

        # Verify client-level async methods
        self.assertTrue(hasattr(client, "close"))
        self.assertTrue(hasattr(client, "validate_session_async"))
        self.assertTrue(hasattr(client, "refresh_session_async"))
        self.assertTrue(hasattr(client, "validate_and_refresh_session_async"))
        self.assertTrue(hasattr(client, "logout_async"))
        self.assertTrue(hasattr(client, "logout_all_async"))
        self.assertTrue(hasattr(client, "me_async"))
        self.assertTrue(hasattr(client, "history_async"))
        self.assertTrue(hasattr(client, "my_tenants_async"))
        self.assertTrue(hasattr(client, "select_tenant_async"))
        self.assertTrue(hasattr(client, "validate_permissions_async"))
        self.assertTrue(hasattr(client, "validate_roles_async"))
        self.assertTrue(hasattr(client, "validate_tenant_permissions_async"))
        self.assertTrue(hasattr(client, "validate_tenant_roles_async"))
        self.assertTrue(hasattr(client, "get_matched_permissions_async"))
        self.assertTrue(hasattr(client, "get_matched_roles_async"))
        self.assertTrue(hasattr(client, "get_matched_tenant_permissions_async"))
        self.assertTrue(hasattr(client, "get_matched_tenant_roles_async"))
        self.assertTrue(hasattr(client, "exchange_access_key_async"))

    # === OTP Async Method Tests ===

    @patch("descope.authmethod.otp.OTP.sign_up")
    async def test_async_otp_sign_up(self, mock_sign_up):
        """Test monkey-patched async OTP sign up."""
        # Setup mock return value
        mock_sign_up.return_value = "t***@example.com"

        # Create client with async methods
        client = AsyncDescopeClient(project_id=self.project_id)

        # Test async method
        result = await client.otp.sign_up_async(
            DeliveryMethod.EMAIL, "test@example.com"
        )

        # Verify result and method call
        self.assertEqual(result, "t***@example.com")
        mock_sign_up.assert_called_once_with(DeliveryMethod.EMAIL, "test@example.com")

    @patch("descope.authmethod.otp.OTP.verify_code")
    async def test_async_otp_verify(self, mock_verify):
        """Test monkey-patched async OTP verify."""
        # Setup mock return value
        mock_verify.return_value = {"sessionToken": "token123"}

        # Create client with async methods
        client = AsyncDescopeClient(project_id=self.project_id)

        # Test async method
        result = await client.otp.verify_code_async(
            DeliveryMethod.EMAIL, "test@example.com", "123456"
        )

        # Verify result
        self.assertEqual(result, {"sessionToken": "token123"})
        mock_verify.assert_called_once_with(
            DeliveryMethod.EMAIL, "test@example.com", "123456"
        )

    @patch("descope.authmethod.otp.OTP.sign_up_or_in")
    async def test_async_otp_sign_up_or_in(self, mock_sign_up_or_in):
        """Test async OTP sign up or in."""
        mock_sign_up_or_in.return_value = "t***@example.com"

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.otp.sign_up_or_in_async(
            DeliveryMethod.EMAIL, "test@example.com"
        )

        self.assertEqual(result, "t***@example.com")
        mock_sign_up_or_in.assert_called_once_with(
            DeliveryMethod.EMAIL, "test@example.com"
        )

    @patch("descope.authmethod.otp.OTP.update_user_email")
    async def test_async_otp_update_user_email(self, mock_update_email):
        """Test async OTP update user email."""
        mock_update_email.return_value = "n***@example.com"

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.otp.update_user_email_async(
            "test@example.com", "new@example.com", "refresh_token"
        )

        self.assertEqual(result, "n***@example.com")
        mock_update_email.assert_called_once_with(
            "test@example.com", "new@example.com", "refresh_token"
        )

    @patch("descope.authmethod.otp.OTP.update_user_phone")
    async def test_async_otp_update_user_phone(self, mock_update_phone):
        """Test async OTP update user phone."""
        mock_update_phone.return_value = "+1***1234"

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.otp.update_user_phone_async(
            "+1234567890", "+1987654321", "refresh_token"
        )

        self.assertEqual(result, "+1***1234")
        mock_update_phone.assert_called_once_with(
            "+1234567890", "+1987654321", "refresh_token"
        )

    # === MagicLink Async Method Tests ===

    @patch("descope.authmethod.magiclink.MagicLink.sign_up")
    async def test_async_magiclink_sign_up(self, mock_sign_up):
        """Test async magic link sign up."""
        mock_sign_up.return_value = "t***@example.com"

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.magiclink.sign_up_async(
            DeliveryMethod.EMAIL, "test@example.com", "http://localhost/callback"
        )

        self.assertEqual(result, "t***@example.com")
        mock_sign_up.assert_called_once_with(
            DeliveryMethod.EMAIL, "test@example.com", "http://localhost/callback"
        )

    @patch("descope.authmethod.magiclink.MagicLink.sign_in")
    async def test_async_magiclink_sign_in(self, mock_sign_in):
        """Test async magic link sign in."""
        mock_sign_in.return_value = "t***@example.com"

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.magiclink.sign_in_async(
            DeliveryMethod.EMAIL, "test@example.com", "http://localhost/callback"
        )

        self.assertEqual(result, "t***@example.com")
        mock_sign_in.assert_called_once_with(
            DeliveryMethod.EMAIL, "test@example.com", "http://localhost/callback"
        )

    @patch("descope.authmethod.magiclink.MagicLink.verify")
    async def test_async_magiclink_verify(self, mock_verify):
        """Test async magic link verify."""
        mock_response = {"sessionToken": "token123"}
        mock_verify.return_value = mock_response

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.magiclink.verify_async("verification_token")

        self.assertEqual(result, mock_response)
        mock_verify.assert_called_once_with("verification_token")

    # === EnchantedLink Async Method Tests ===

    @patch("descope.authmethod.enchantedlink.EnchantedLink.sign_in")
    async def test_async_enchantedlink_sign_in(self, mock_sign_in):
        """Test async enchanted link sign in."""
        mock_sign_in.return_value = "link-id-123"

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.enchantedlink.sign_in_async("test@example.com")

        self.assertEqual(result, "link-id-123")
        mock_sign_in.assert_called_once_with("test@example.com")

    @patch("descope.authmethod.enchantedlink.EnchantedLink.verify")
    async def test_async_enchantedlink_verify(self, mock_verify):
        """Test async enchanted link verify."""
        mock_response = {"sessionToken": "token123"}
        mock_verify.return_value = mock_response

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.enchantedlink.verify_async("link-id-123")

        self.assertEqual(result, mock_response)
        mock_verify.assert_called_once_with("link-id-123")

    @patch("descope.authmethod.enchantedlink.EnchantedLink.get_session")
    async def test_async_enchantedlink_get_session(self, mock_get_session):
        """Test async enchanted link get session."""
        mock_response = {"sessionToken": "token123"}
        mock_get_session.return_value = mock_response

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.enchantedlink.get_session_async("link-id-123")

        self.assertEqual(result, mock_response)
        mock_get_session.assert_called_once_with("link-id-123")

    # === OAuth Async Method Tests ===

    @patch("descope.authmethod.oauth.OAuth.exchange_token")
    async def test_async_oauth_exchange_token(self, mock_exchange):
        """Test async OAuth exchange token."""
        mock_response = {"sessionToken": "token123"}
        mock_exchange.return_value = mock_response

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.oauth.exchange_token_async("auth_code")

        self.assertEqual(result, mock_response)
        mock_exchange.assert_called_once_with("auth_code")

    # === SSO Async Method Tests ===

    @patch("descope.authmethod.sso.SSO.exchange_token")
    async def test_async_sso_exchange_token(self, mock_exchange):
        """Test async SSO exchange token."""
        mock_response = {"sessionToken": "token123"}
        mock_exchange.return_value = mock_response

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.sso.exchange_token_async("auth_code")

        self.assertEqual(result, mock_response)
        mock_exchange.assert_called_once_with("auth_code")

    # === SAML Async Method Tests (Deprecated) ===

    @patch("descope.authmethod.saml.SAML.start")
    async def test_async_saml_start(self, mock_start):
        """Test async SAML start (deprecated)."""
        mock_start.return_value = "https://saml.provider.com/auth"

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.saml.start_async(
            "test-tenant", "http://localhost/callback"
        )

        self.assertEqual(result, "https://saml.provider.com/auth")
        mock_start.assert_called_once_with("test-tenant", "http://localhost/callback")

    @patch("descope.authmethod.saml.SAML.exchange_token")
    async def test_async_saml_exchange_token(self, mock_exchange):
        """Test async SAML exchange token (deprecated)."""
        mock_response = {"sessionToken": "token123"}
        mock_exchange.return_value = mock_response

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.saml.exchange_token_async("saml_response")

        self.assertEqual(result, mock_response)
        mock_exchange.assert_called_once_with("saml_response")

    # === TOTP Async Method Tests ===

    @patch("descope.authmethod.totp.TOTP.sign_in_code")
    async def test_async_totp_sign_in_code(self, mock_sign_in):
        """Test async TOTP sign in with code."""
        mock_response = {"sessionToken": "token123"}
        mock_sign_in.return_value = mock_response

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.totp.sign_in_code_async("test@example.com", "123456")

        self.assertEqual(result, mock_response)
        mock_sign_in.assert_called_once_with("test@example.com", "123456")

    @patch("descope.authmethod.totp.TOTP.update_user")
    async def test_async_totp_update_user(self, mock_update):
        """Test async TOTP update user."""
        mock_response = {
            "provisioningURL": "otpauth://totp/updated",
            "key": "NEWSECRET",
        }
        mock_update.return_value = mock_response

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.totp.update_user_async(
            "test@example.com", "refresh_token"
        )

        self.assertEqual(result, mock_response)
        mock_update.assert_called_once_with("test@example.com", "refresh_token")

    # === WebAuthn Async Method Tests ===

    @patch("descope.authmethod.webauthn.WebAuthn.sign_up_finish")
    async def test_async_webauthn_sign_up_finish(self, mock_finish):
        """Test async WebAuthn sign up finish."""
        mock_response = {"sessionToken": "token123"}
        mock_finish.return_value = mock_response

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.webauthn.sign_up_finish_async(
            "transaction_id", {"response": "data"}
        )

        self.assertEqual(result, mock_response)
        mock_finish.assert_called_once_with("transaction_id", {"response": "data"})

    @patch("descope.authmethod.webauthn.WebAuthn.sign_in_start")
    async def test_async_webauthn_sign_in_start(self, mock_start):
        """Test async WebAuthn sign in start."""
        mock_response = {"transactionId": "txn123", "options": {}}
        mock_start.return_value = mock_response

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.webauthn.sign_in_start_async("test@example.com")

        self.assertEqual(result, mock_response)
        mock_start.assert_called_once_with("test@example.com")

    @patch("descope.authmethod.webauthn.WebAuthn.sign_in_finish")
    async def test_async_webauthn_sign_in_finish(self, mock_finish):
        """Test async WebAuthn sign in finish."""
        mock_response = {"sessionToken": "token123"}
        mock_finish.return_value = mock_response

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.webauthn.sign_in_finish_async(
            "transaction_id", {"response": "data"}
        )

        self.assertEqual(result, mock_response)
        mock_finish.assert_called_once_with("transaction_id", {"response": "data"})

    @patch("descope.authmethod.webauthn.WebAuthn.sign_up_or_in_start")
    async def test_async_webauthn_sign_up_or_in_start(self, mock_start):
        """Test async WebAuthn sign up or in start."""
        mock_response = {"transactionId": "txn123", "options": {}}
        mock_start.return_value = mock_response

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.webauthn.sign_up_or_in_start_async("test@example.com")

        self.assertEqual(result, mock_response)
        mock_start.assert_called_once_with("test@example.com")

    @patch("descope.authmethod.webauthn.WebAuthn.update_start")
    async def test_async_webauthn_update_start(self, mock_start):
        """Test async WebAuthn update start."""
        mock_response = {"transactionId": "txn123", "options": {}}
        mock_start.return_value = mock_response

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.webauthn.update_start_async(
            "test@example.com", "refresh_token"
        )

        self.assertEqual(result, mock_response)
        mock_start.assert_called_once_with("test@example.com", "refresh_token")

    @patch("descope.authmethod.webauthn.WebAuthn.update_finish")
    async def test_async_webauthn_update_finish(self, mock_finish):
        """Test async WebAuthn update finish."""
        mock_response = {"sessionToken": "token123"}
        mock_finish.return_value = mock_response

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.webauthn.update_finish_async(
            "transaction_id", {"response": "data"}
        )

        self.assertEqual(result, mock_response)
        mock_finish.assert_called_once_with("transaction_id", {"response": "data"})

    # === Password Async Method Tests ===

    @patch("descope.authmethod.password.Password.sign_up")
    async def test_async_password_sign_up(self, mock_sign_up):
        """Test async password sign up."""
        mock_response = {"sessionToken": "token123"}
        mock_sign_up.return_value = mock_response

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.password.sign_up_async("test@example.com", "password123")

        self.assertEqual(result, mock_response)
        mock_sign_up.assert_called_once_with("test@example.com", "password123")

    @patch("descope.authmethod.password.Password.sign_in")
    async def test_async_password_sign_in(self, mock_sign_in):
        """Test async password sign in."""
        mock_response = {"sessionToken": "token123"}
        mock_sign_in.return_value = mock_response

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.password.sign_in_async("test@example.com", "password123")

        self.assertEqual(result, mock_response)
        mock_sign_in.assert_called_once_with("test@example.com", "password123")

    @patch("descope.authmethod.password.Password.send_reset")
    async def test_async_password_send_reset(self, mock_send_reset):
        """Test async password send reset."""
        mock_send_reset.return_value = "t***@example.com"

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.password.send_reset_async(
            "test@example.com", "http://localhost/reset"
        )

        self.assertEqual(result, "t***@example.com")
        mock_send_reset.assert_called_once_with(
            "test@example.com", "http://localhost/reset"
        )

    @patch("descope.authmethod.password.Password.update")
    async def test_async_password_update(self, mock_update):
        """Test async password update."""
        mock_update.return_value = None

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.password.update_async(
            "test@example.com", "newpass123", "refresh_token"
        )

        self.assertIsNone(result)
        mock_update.assert_called_once_with(
            "test@example.com", "newpass123", "refresh_token"
        )

    @patch("descope.authmethod.password.Password.replace")
    async def test_async_password_replace(self, mock_replace):
        """Test async password replace."""
        mock_response = {"sessionToken": "token123"}
        mock_replace.return_value = mock_response

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.password.replace_async(
            "test@example.com", "oldpass", "newpass123"
        )

        self.assertEqual(result, mock_response)
        mock_replace.assert_called_once_with(
            "test@example.com", "oldpass", "newpass123"
        )

    @patch("descope.authmethod.password.Password.get_policy")
    async def test_async_password_get_policy(self, mock_get_policy):
        """Test async password get policy."""
        mock_policy = {"minLength": 8, "requireUppercase": True}
        mock_get_policy.return_value = mock_policy

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.password.get_policy_async()

        self.assertEqual(result, mock_policy)
        mock_get_policy.assert_called_once()

    # === Client-Level Async Method Tests ===

    @patch("descope.descope_client.DescopeClient.validate_session")
    async def test_async_client_validate_session(self, mock_validate):
        """Test async client-level validate session."""
        mock_response = {"userId": "user123", "tenantId": "tenant456"}
        mock_validate.return_value = mock_response

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.validate_session_async("session_token")

        self.assertEqual(result, mock_response)
        mock_validate.assert_called_once_with("session_token")

    @patch("descope.descope_client.DescopeClient.refresh_session")
    async def test_async_client_refresh_session(self, mock_refresh):
        """Test async client-level refresh session."""
        mock_response = {"sessionToken": "new_token123"}
        mock_refresh.return_value = mock_response

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.refresh_session_async("refresh_token")

        self.assertEqual(result, mock_response)
        mock_refresh.assert_called_once_with("refresh_token")

    @patch("descope.descope_client.DescopeClient.logout")
    async def test_async_client_logout(self, mock_logout):
        """Test async client-level logout."""
        mock_logout.return_value = None

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.logout_async("refresh_token")

        self.assertIsNone(result)
        mock_logout.assert_called_once_with("refresh_token")

    @patch("descope.descope_client.DescopeClient.logout_all")
    async def test_async_client_logout_all(self, mock_logout_all):
        """Test async client-level logout all."""
        mock_logout_all.return_value = None

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.logout_all_async("refresh_token")

        self.assertIsNone(result)
        mock_logout_all.assert_called_once_with("refresh_token")

    @patch("descope.descope_client.DescopeClient.me")
    async def test_async_client_me(self, mock_me):
        """Test async client-level me."""
        mock_response = {"userId": "user123", "email": "test@example.com"}
        mock_me.return_value = mock_response

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.me_async("refresh_token")

        self.assertEqual(result, mock_response)
        mock_me.assert_called_once_with("refresh_token")

    @patch("descope.descope_client.DescopeClient.history")
    async def test_async_client_history(self, mock_history):
        """Test async client-level history."""
        mock_response = {"events": [{"event": "login", "timestamp": 1234567890}]}
        mock_history.return_value = mock_response

        client = AsyncDescopeClient(project_id=self.project_id)
        result = await client.history_async("refresh_token")

        self.assertEqual(result, mock_response)
        mock_history.assert_called_once_with("refresh_token")

    # === Error Handling Tests ===

    @patch("descope.authmethod.otp.OTP.sign_up")
    async def test_async_otp_sign_up_error_handling(self, mock_sign_up):
        """Test async OTP sign up error handling."""
        mock_sign_up.side_effect = AuthException(400, "E011001", "Invalid email")

        client = AsyncDescopeClient(project_id=self.project_id)

        with self.assertRaises(AuthException) as cm:
            await client.otp.sign_up_async(DeliveryMethod.EMAIL, "invalid-email")

        self.assertEqual(cm.exception.status_code, 400)
        self.assertEqual(cm.exception.error_type, "E011001")
        self.assertEqual(cm.exception.error_message, "Invalid email")

    async def test_async_client_close(self):
        """Test async client close method."""
        client = AsyncDescopeClient(project_id=self.project_id)

        # Verify the method exists and is callable
        self.assertTrue(hasattr(client, "close"))
        self.assertTrue(callable(client.close))

        # Close should not raise an exception
        await client.close()


if __name__ == "__main__":
    unittest.main()
