import pytest

from descope import AuthException
from descope.authmethod.webauthn import WebAuthn
from descope.common import (
    REFRESH_SESSION_COOKIE_NAME,
    EndpointsV1,
    LoginOptions,
)
from tests.conftest import PROJECT_ID, assert_http_called, make_response
from tests.testutils import PUBLIC_KEY_DICT, VALID_REFRESH_TOKEN, VALID_SESSION_TOKEN

from . import common


class TestWebAuthn:
    def test_compose_sign_up_start_body(self):
        assert WebAuthn._compose_sign_up_start_body("dummy@dummy.com", {"name": "dummy"}, "https://example.com") == {
            "user": {"loginId": "dummy@dummy.com", "name": "dummy"},
            "origin": "https://example.com",
        }

    def test_compose_sign_in_start_body(self):
        assert WebAuthn._compose_sign_in_start_body("dummy@dummy.com", "https://example.com") == {
            "loginId": "dummy@dummy.com",
            "origin": "https://example.com",
            "loginOptions": {},
        }

    def test_compose_sign_up_or_in_start_body(self):
        assert WebAuthn._compose_sign_up_or_in_start_body("dummy@dummy.com", "https://example.com") == {
            "loginId": "dummy@dummy.com",
            "origin": "https://example.com",
        }

    def test_compose_finish_bodies(self):
        assert WebAuthn._compose_sign_up_in_finish_body("t01", "resp01") == {
            "transactionId": "t01",
            "response": "resp01",
        }
        assert WebAuthn._compose_update_finish_body("t01", "resp01") == {
            "transactionId": "t01",
            "response": "resp01",
        }

    def test_compose_update_start_body(self):
        assert WebAuthn._compose_update_start_body("dummy@dummy.com", "https://example.com") == {
            "loginId": "dummy@dummy.com",
            "origin": "https://example.com",
        }

    async def test_sign_up_start(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)

        # Validation errors
        with pytest.raises(AuthException):
            await client.invoke(client.webauthn.sign_up_start("", "https://example.com"))
        with pytest.raises(AuthException):
            await client.invoke(client.webauthn.sign_up_start("id1", ""))

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.webauthn.sign_up_start("id1", "https://example.com"))

        # Success + payload
        with client.mock_post(make_response({"transactionId": "txn1", "options": "{}"})) as mock_post:
            result = await client.invoke(client.webauthn.sign_up_start("id1", "https://example.com"))
        assert result is not None
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_up_auth_webauthn_start_path}",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}",
                "x-descope-project-id": PROJECT_ID,
            },
            params=None,
            json={"user": {"loginId": "id1"}, "origin": "https://example.com"},
            follow_redirects=False,
        )

    async def test_sign_up_finish(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)

        # Validation errors
        with pytest.raises(AuthException):
            await client.invoke(client.webauthn.sign_up_finish("", "resp"))
        with pytest.raises(AuthException):
            await client.invoke(client.webauthn.sign_up_finish(None, "resp"))
        with pytest.raises(AuthException):
            await client.invoke(client.webauthn.sign_up_finish("t01", ""))
        with pytest.raises(AuthException):
            await client.invoke(client.webauthn.sign_up_finish("t01", None))

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.webauthn.sign_up_finish("t01", "resp"))

        # Success
        success_resp = make_response(
            {"sessionJwt": VALID_SESSION_TOKEN},
            cookies={REFRESH_SESSION_COOKIE_NAME: VALID_REFRESH_TOKEN},
        )
        with client.mock_post(success_resp) as mock_post:
            result = await client.invoke(client.webauthn.sign_up_finish("t01", "resp01"))
        assert result is not None
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_up_auth_webauthn_finish_path}",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}",
                "x-descope-project-id": PROJECT_ID,
            },
            params=None,
            json={"transactionId": "t01", "response": "resp01"},
            follow_redirects=False,
        )

    async def test_sign_in_start(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)

        # Validation errors
        with pytest.raises(AuthException):
            await client.invoke(client.webauthn.sign_in_start("", "https://example.com"))
        with pytest.raises(AuthException):
            await client.invoke(client.webauthn.sign_in_start("id", ""))
        with pytest.raises(AuthException):
            await client.invoke(client.webauthn.sign_in_start("id", "https://example.com", LoginOptions(mfa=True)))

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.webauthn.sign_in_start("id1", "https://example.com"))

        # Success + payload
        with client.mock_post(make_response({"transactionId": "txn1"})) as mock_post:
            result = await client.invoke(client.webauthn.sign_in_start("id1", "https://example.com"))
        assert result is not None
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_in_auth_webauthn_start_path}",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}",
                "x-descope-project-id": PROJECT_ID,
            },
            params=None,
            json={"loginId": "id1", "origin": "https://example.com", "loginOptions": {}},
            follow_redirects=False,
        )

    async def test_sign_in_start_with_login_options(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)
        lo = LoginOptions(stepup=True, custom_claims={"k1": "v1"})

        with client.mock_post(make_response({"transactionId": "txn1"})) as mock_post:
            await client.invoke(client.webauthn.sign_in_start("id1", "https://example.com", lo, "refresh"))
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_in_auth_webauthn_start_path}",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}:refresh",
                "x-descope-project-id": PROJECT_ID,
            },
            params=None,
            json={
                "loginId": "id1",
                "origin": "https://example.com",
                "loginOptions": {"stepup": True, "customClaims": {"k1": "v1"}, "mfa": False},
            },
            follow_redirects=False,
        )

    async def test_sign_in_finish(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)

        # Validation errors
        with pytest.raises(AuthException):
            await client.invoke(client.webauthn.sign_in_finish("", "resp"))
        with pytest.raises(AuthException):
            await client.invoke(client.webauthn.sign_in_finish(None, "resp"))
        with pytest.raises(AuthException):
            await client.invoke(client.webauthn.sign_in_finish("t01", ""))
        with pytest.raises(AuthException):
            await client.invoke(client.webauthn.sign_in_finish("t01", None))

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.webauthn.sign_in_finish("t01", "resp"))

        # Success
        success_resp = make_response(
            {"sessionJwt": VALID_SESSION_TOKEN},
            cookies={REFRESH_SESSION_COOKIE_NAME: VALID_REFRESH_TOKEN},
        )
        with client.mock_post(success_resp) as mock_post:
            result = await client.invoke(client.webauthn.sign_in_finish("t01", "resp01"))
        assert result is not None
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_in_auth_webauthn_finish_path}",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}",
                "x-descope-project-id": PROJECT_ID,
            },
            params=None,
            json={"transactionId": "t01", "response": "resp01"},
            follow_redirects=False,
        )

    async def test_sign_up_or_in_start(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)

        # Validation errors
        with pytest.raises(AuthException):
            await client.invoke(client.webauthn.sign_up_or_in_start("", "https://example.com"))
        with pytest.raises(AuthException):
            await client.invoke(client.webauthn.sign_up_or_in_start("id", ""))

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.webauthn.sign_up_or_in_start("id1", "https://example.com"))

        # Success + payload
        with client.mock_post(make_response({"transactionId": "txn1", "create": True})) as mock_post:
            result = await client.invoke(client.webauthn.sign_up_or_in_start("id1", "https://example.com"))
        assert result is not None
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_up_or_in_auth_webauthn_start_path}",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}",
                "x-descope-project-id": PROJECT_ID,
            },
            params=None,
            json={"loginId": "id1", "origin": "https://example.com"},
            follow_redirects=False,
        )

    async def test_update_start(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)
        refresh_token = VALID_REFRESH_TOKEN

        # Validation errors
        with pytest.raises(AuthException):
            await client.invoke(client.webauthn.update_start("", refresh_token, "https://example.com"))
        with pytest.raises(AuthException):
            await client.invoke(client.webauthn.update_start(None, refresh_token, "https://example.com"))
        with pytest.raises(AuthException):
            await client.invoke(client.webauthn.update_start("id", "", "https://example.com"))
        with pytest.raises(AuthException):
            await client.invoke(client.webauthn.update_start("id", None, "https://example.com"))

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.webauthn.update_start("id1", refresh_token, "https://example.com"))

        # Success + payload
        with client.mock_post(make_response({"transactionId": "txn1"})) as mock_post:
            result = await client.invoke(client.webauthn.update_start("id1", refresh_token, "https://example.com"))
        assert result is not None
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.update_auth_webauthn_start_path}",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}:{refresh_token}",
                "x-descope-project-id": PROJECT_ID,
            },
            params=None,
            json={"loginId": "id1", "origin": "https://example.com"},
            follow_redirects=False,
        )

    async def test_update_finish(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)

        # Validation errors
        with pytest.raises(AuthException):
            await client.invoke(client.webauthn.update_finish("", "resp"))
        with pytest.raises(AuthException):
            await client.invoke(client.webauthn.update_finish(None, "resp"))
        with pytest.raises(AuthException):
            await client.invoke(client.webauthn.update_finish("t01", ""))
        with pytest.raises(AuthException):
            await client.invoke(client.webauthn.update_finish("t01", None))

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.webauthn.update_finish("t01", "resp"))

        # Success (returns None)
        with client.mock_post(make_response({})) as mock_post:
            result = await client.invoke(client.webauthn.update_finish("t01", "resp01"))
        assert result is None
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.update_auth_webauthn_finish_path}",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}",
                "x-descope-project-id": PROJECT_ID,
            },
            params=None,
            json={"transactionId": "t01", "response": "resp01"},
            follow_redirects=False,
        )
