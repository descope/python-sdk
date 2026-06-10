import pytest

from descope import AuthException
from descope.authmethod.password import Password
from descope.common import (
    REFRESH_SESSION_COOKIE_NAME,
    EndpointsV1,
)
from tests.conftest import PROJECT_ID, assert_http_called, make_response
from tests.testutils import PUBLIC_KEY_DICT, VALID_REFRESH_TOKEN, VALID_SESSION_TOKEN

from . import common


class TestPassword:
    def test_compose_signup_body(self):
        assert Password._compose_signup_body("id1", "pw1", {"name": "John"}) == {
            "loginId": "id1",
            "password": "pw1",
            "user": {"name": "John"},
        }
        assert Password._compose_signup_body("id1", "pw1", None) == {
            "loginId": "id1",
            "password": "pw1",
        }

    async def test_sign_up(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)

        # Validation errors
        with pytest.raises(AuthException):
            await client.invoke(client.password.sign_up("", "pw1"))
        with pytest.raises(AuthException):
            await client.invoke(client.password.sign_up(None, "pw1"))
        with pytest.raises(AuthException):
            await client.invoke(client.password.sign_up("id", ""))
        with pytest.raises(AuthException):
            await client.invoke(client.password.sign_up("id", None))

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.password.sign_up("dummy@dummy.com", "pw123"))

        # Success + payload
        success_resp = make_response(
            {"sessionJwt": VALID_SESSION_TOKEN},
            cookies={REFRESH_SESSION_COOKIE_NAME: VALID_REFRESH_TOKEN},
        )
        with client.mock_post(success_resp) as mock_post:
            result = await client.invoke(client.password.sign_up("dummy@dummy.com", "pw123"))
        assert result is not None
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_up_password_path}",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}",
                "x-descope-project-id": PROJECT_ID,
            },
            params=None,
            json={"loginId": "dummy@dummy.com", "password": "pw123"},
            follow_redirects=False,
        )

    async def test_sign_in(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)

        # Validation errors
        with pytest.raises(AuthException):
            await client.invoke(client.password.sign_in("", "pw1"))
        with pytest.raises(AuthException):
            await client.invoke(client.password.sign_in(None, "pw1"))
        with pytest.raises(AuthException):
            await client.invoke(client.password.sign_in("id", ""))
        with pytest.raises(AuthException):
            await client.invoke(client.password.sign_in("id", None))

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.password.sign_in("dummy@dummy.com", "pw123"))

        # Success + payload
        success_resp = make_response(
            {"sessionJwt": VALID_SESSION_TOKEN},
            cookies={REFRESH_SESSION_COOKIE_NAME: VALID_REFRESH_TOKEN},
        )
        with client.mock_post(success_resp) as mock_post:
            result = await client.invoke(client.password.sign_in("dummy@dummy.com", "pw123"))
        assert result is not None
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_in_password_path}",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}",
                "x-descope-project-id": PROJECT_ID,
            },
            params=None,
            json={"loginId": "dummy@dummy.com", "password": "pw123"},
            follow_redirects=False,
        )

    async def test_send_reset(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)

        # Validation errors
        with pytest.raises(AuthException):
            await client.invoke(client.password.send_reset(""))
        with pytest.raises(AuthException):
            await client.invoke(client.password.send_reset(None))

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.password.send_reset("dummy@dummy.com"))

        # Success + payload
        with client.mock_post(
            make_response({"resetMethod": "magiclink", "maskedEmail": "du***@***my.com"})
        ) as mock_post:
            result = await client.invoke(client.password.send_reset("dummy@dummy.com", "https://redirect.here.com"))
        assert result is not None
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.send_reset_password_path}",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}",
                "x-descope-project-id": PROJECT_ID,
            },
            params=None,
            json={"loginId": "dummy@dummy.com", "redirectUrl": "https://redirect.here.com"},
            follow_redirects=False,
        )

    async def test_update(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)
        refresh_token = VALID_REFRESH_TOKEN

        # Validation errors
        with pytest.raises(AuthException):
            await client.invoke(client.password.update("", "newpw", refresh_token))
        with pytest.raises(AuthException):
            await client.invoke(client.password.update(None, "newpw", refresh_token))
        with pytest.raises(AuthException):
            await client.invoke(client.password.update("id", "", refresh_token))
        with pytest.raises(AuthException):
            await client.invoke(client.password.update("id", None, refresh_token))
        with pytest.raises(AuthException):
            await client.invoke(client.password.update("id", "newpw", ""))
        with pytest.raises(AuthException):
            await client.invoke(client.password.update("id", "newpw", None))

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.password.update("dummy@dummy.com", "newpw", refresh_token))

        # Success (returns None)
        with client.mock_post(make_response({})) as mock_post:
            result = await client.invoke(client.password.update("dummy@dummy.com", "newpw", refresh_token))
        assert result is None
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.update_password_path}",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}:{refresh_token}",
                "x-descope-project-id": PROJECT_ID,
            },
            params=None,
            json={"loginId": "dummy@dummy.com", "newPassword": "newpw"},
            follow_redirects=False,
        )

    async def test_replace(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)

        # Validation errors
        with pytest.raises(AuthException):
            await client.invoke(client.password.replace("", "oldpw", "newpw"))
        with pytest.raises(AuthException):
            await client.invoke(client.password.replace(None, "oldpw", "newpw"))
        with pytest.raises(AuthException):
            await client.invoke(client.password.replace("id", "", "newpw"))
        with pytest.raises(AuthException):
            await client.invoke(client.password.replace("id", None, "newpw"))
        with pytest.raises(AuthException):
            await client.invoke(client.password.replace("id", "oldpw", ""))
        with pytest.raises(AuthException):
            await client.invoke(client.password.replace("id", "oldpw", None))

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.password.replace("dummy@dummy.com", "oldpw", "newpw"))

        # Success + payload
        success_resp = make_response(
            {"sessionJwt": VALID_SESSION_TOKEN},
            cookies={REFRESH_SESSION_COOKIE_NAME: VALID_REFRESH_TOKEN},
        )
        with client.mock_post(success_resp) as mock_post:
            result = await client.invoke(client.password.replace("dummy@dummy.com", "oldpw", "newpw"))
        assert result is not None
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.replace_password_path}",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}",
                "x-descope-project-id": PROJECT_ID,
            },
            params=None,
            json={
                "loginId": "dummy@dummy.com",
                "oldPassword": "oldpw",
                "newPassword": "newpw",
            },
            follow_redirects=False,
        )

    async def test_get_policy(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)

        # HTTP error
        with client.mock_get(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.password.get_policy())

        # Success + payload
        with client.mock_get(make_response({"minLength": 8, "lowercase": True})) as mock_get:
            result = await client.invoke(client.password.get_policy())
        assert result is not None
        assert_http_called(
            mock_get,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.password_policy_path}",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}",
                "x-descope-project-id": PROJECT_ID,
            },
            params=None,
            follow_redirects=True,
        )
